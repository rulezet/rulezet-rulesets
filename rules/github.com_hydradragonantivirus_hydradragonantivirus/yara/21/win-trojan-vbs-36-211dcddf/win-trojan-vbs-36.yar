rule Win_Trojan_VBS_36
{
strings:
	$a0 = { 43687228 }

	$a1 = { 4e657874 }

	$a2 = { 456e64 }

	$a3 = { 46756e6374696f6e }

	$a4 = { 205b4b5d416c616d6172 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}