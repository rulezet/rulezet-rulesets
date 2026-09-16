rule Win_Trojan_Cascade_22
{
strings:
	$a0 = { b74d01bc800631343124464c75f8 }


condition:
	$a0
}