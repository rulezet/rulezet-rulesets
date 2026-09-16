rule Win_Trojan_Panic_1
{
strings:
	$a0 = { 3d8bd583c21ecd218946318bd8b43fb903008bd583c2 }


condition:
	$a0
}