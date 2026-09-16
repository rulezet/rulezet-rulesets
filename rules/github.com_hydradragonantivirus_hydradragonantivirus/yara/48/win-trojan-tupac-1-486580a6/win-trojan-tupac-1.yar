rule Win_Trojan_Tupac_1
{
strings:
	$a0 = { 25cd210e1fb80135cd213e8c860f053e899e0d058d96 }


condition:
	$a0
}