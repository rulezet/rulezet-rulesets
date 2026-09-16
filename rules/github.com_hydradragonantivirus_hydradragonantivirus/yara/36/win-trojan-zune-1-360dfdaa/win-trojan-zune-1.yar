rule Win_Trojan_Zune_1
{
strings:
	$a0 = { be0000b2??8bfe03fe2e30154681fe010a76f2 }


condition:
	$a0
}