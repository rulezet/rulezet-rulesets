rule Win_Trojan_Black_2
{
strings:
	$a0 = { bacc02b409cd21b44ccd21ba0003b4 }


condition:
	$a0
}