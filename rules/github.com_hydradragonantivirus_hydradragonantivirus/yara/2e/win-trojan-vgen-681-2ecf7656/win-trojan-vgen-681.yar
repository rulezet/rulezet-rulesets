rule Win_Trojan_VGEN_681
{
strings:
	$a0 = { e800005e81ee0c018beebea6012e8ab60501b91d0203f52e8a2432e62e882446e2f5bea601bfa601b91d028b042e3b86 }


condition:
	$a0
}