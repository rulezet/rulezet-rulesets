rule Win_Trojan_Byworm_4
{
strings:
	$a0 = { e800005d81ed????be????8b86????b9??02f7123102d10a0102ff02ff0a2902d102d1022902ff0aff020102d10a3102f7124646e2dc }


condition:
	$a0
}