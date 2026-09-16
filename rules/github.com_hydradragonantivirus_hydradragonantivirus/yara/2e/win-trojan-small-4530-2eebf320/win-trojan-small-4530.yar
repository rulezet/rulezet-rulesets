rule Win_Trojan_Small_4530
{
strings:
	$a0 = { bdf9954000babba040008b1affd301d5e83600000050e8 }


condition:
	$a0
}