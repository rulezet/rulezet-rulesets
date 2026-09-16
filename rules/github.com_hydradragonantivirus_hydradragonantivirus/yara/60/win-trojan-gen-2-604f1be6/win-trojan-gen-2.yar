rule Win_Trojan_Gen_2
{
strings:
	$a0 = { cd21ba9305bd0a0033c9b43ccd21720593b43ecd2183c2094d75edba9005b43bcd21803e1107 }


condition:
	$a0
}