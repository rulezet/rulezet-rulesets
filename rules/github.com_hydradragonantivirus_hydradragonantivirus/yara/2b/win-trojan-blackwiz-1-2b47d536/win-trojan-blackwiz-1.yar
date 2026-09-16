rule Win_Trojan_BlackWiz_1
{
strings:
	$a0 = { b8001acd215e8b1cb90308b80040cd21 }


condition:
	$a0
}