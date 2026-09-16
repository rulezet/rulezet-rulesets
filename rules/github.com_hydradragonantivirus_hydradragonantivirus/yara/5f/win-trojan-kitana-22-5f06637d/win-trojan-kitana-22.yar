rule Win_Trojan_Kitana_22
{
strings:
	$a0 = { 9c530e0e1f8bf3ff0e????cd12b166d3c08ec033fff3a44141fdae8745e1[0-1]abb85300e2f6 }


condition:
	$a0
}