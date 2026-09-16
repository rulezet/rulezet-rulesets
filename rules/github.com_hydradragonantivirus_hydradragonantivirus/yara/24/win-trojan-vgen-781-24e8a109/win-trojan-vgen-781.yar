rule Win_Trojan_VGEN_781
{
strings:
	$a0 = { ee0301bf000103f7b98302bb1701fce96802c70683030001ba4501b8023dcd2193b44033c9cd21b98302e81b00b4 }


condition:
	$a0
}