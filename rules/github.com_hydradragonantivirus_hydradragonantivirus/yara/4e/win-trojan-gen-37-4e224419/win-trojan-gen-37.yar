rule Win_Trojan_Gen_37
{
strings:
	$a0 = { 8ed8be0000b02eb4803a04751bb03a3a44017514b026 }


condition:
	$a0
}