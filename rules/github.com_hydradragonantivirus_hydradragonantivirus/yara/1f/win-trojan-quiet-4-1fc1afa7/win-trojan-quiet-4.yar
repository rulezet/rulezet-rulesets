rule Win_Trojan_Quiet_4
{
strings:
	$a0 = { a005b430cd213c03720ae89101800ec60700741f8e06a0 }


condition:
	$a0
}