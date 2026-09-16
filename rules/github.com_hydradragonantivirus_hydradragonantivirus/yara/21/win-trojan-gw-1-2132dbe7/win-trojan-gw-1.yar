rule Win_Trojan_GW_1
{
strings:
	$a0 = { 47572ea0e500b90203bbe600e80100c32e300743e2fac3 }


condition:
	$a0
}