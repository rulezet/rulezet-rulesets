rule malicious_SVG_1 : hardened
{
	meta:
		author = "OPSWAT"
		description = "Identify malicious JavaScript on SVG files"
		score = 75

	strings:
		$tag_xml_header = {3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d}
		$tag_svg_start = {3c 73 76 67}
		$tag_svg_end = {3c 2f 73 76 67 3e}
		$tag_script_start = {3c 73 63 72 69 70 74}
		$tag_script_end = {3c 2f 73 63 72 69 70 74}
		$st1_cdata = {3c 21 5b 43 44 41 54 41 5b}
		$st2_atob = {61 74 6f 62 28}
		$st2_charcode = {63 68 61 72 43 6f 64 65 41 74 28}
		$st2_split = {2e 73 70 6c 69 74 28}
		$st2_map = {2e 6d 61 70 28}

	condition:
		all of ( $tag* ) and $st1_cdata and all of ( $st2* ) and for all of ( $st* ) : ( @ > @tag_script_start and @ < @tag_script_end )
}