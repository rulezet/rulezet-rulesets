rule Win_Trojan_Gula_2
{
strings:
	$a0 = { 030089860a01b440b92b018bd583ea12cd2133c933d2b80042cd21b440b90300ba090101eacd21 }


condition:
	$a0
}