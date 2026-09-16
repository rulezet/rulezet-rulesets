rule Win_Trojan_Gen_133
{
strings:
	$a0 = { 03532effb55d04bbde03b97f00582e300143e2fa5be8 }


condition:
	$a0
}