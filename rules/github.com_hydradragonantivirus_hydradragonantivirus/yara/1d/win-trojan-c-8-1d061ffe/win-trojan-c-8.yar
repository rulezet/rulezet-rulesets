rule Win_Trojan_C_8
{
strings:
	$a0 = { fc90b9e50533d9903105310d424346404790e2f1 }


condition:
	$a0
}