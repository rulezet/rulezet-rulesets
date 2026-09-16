rule Win_Trojan_Gro_2
{
strings:
	$a0 = { 8c369e89a164f7b1c19d721df0b567a2a27babb475daaa8639ba0263ec63be86d50db67f36b5ae46 }


condition:
	$a0
}