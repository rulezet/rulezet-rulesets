rule Win_Trojan_Small_4272
{
strings:
	$a0 = { 608d5c24208b5c230066bb0000[0-255]545983e9e7897107c3 }


condition:
	$a0
}