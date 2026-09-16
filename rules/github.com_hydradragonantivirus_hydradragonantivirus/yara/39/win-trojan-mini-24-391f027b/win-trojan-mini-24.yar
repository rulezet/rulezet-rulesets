rule Win_Trojan_Mini_24
{
strings:
	$a0 = { be0002bf84008bd603d78beacd21b44eba7a01b92600cd217254b8023d8bd583c21ecd21723c8bd8b43f8bcf8bd5 }


condition:
	$a0
}