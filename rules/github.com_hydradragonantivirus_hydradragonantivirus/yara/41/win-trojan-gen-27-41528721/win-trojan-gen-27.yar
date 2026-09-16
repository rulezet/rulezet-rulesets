rule Win_Trojan_Gen_27
{
strings:
	$a0 = { f501b90500b440cd218b1481c20301b9b505908dbe3d078db60801e868008d963d07b440cd21 }


condition:
	$a0
}