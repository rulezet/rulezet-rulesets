rule Win_Trojan_Gen_83
{
strings:
	$a0 = { 21b4408d960501b96901cd21b43ecd21c3c6865e020006b42fcd2107899e5f02899e6102c3 }


condition:
	$a0
}