rule Win_Trojan_Taiwan_11
{
strings:
	$a0 = { e4210c02e6210633c08ec026a15800 }


condition:
	$a0
}