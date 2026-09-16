rule Win_Trojan_WINTIN_1
{
strings:
	$a0 = { 0671031200ba6d03b90a00b440cd21b43ecd21e80300e983fdb802058b36db028b3edd02cd31c3 }


condition:
	$a0
}