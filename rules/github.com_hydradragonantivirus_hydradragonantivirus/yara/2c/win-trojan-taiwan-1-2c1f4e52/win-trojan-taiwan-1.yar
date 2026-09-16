rule Win_Trojan_Taiwan_1
{
strings:
	$a0 = { 0201268c0e5a0007e4210c02e621fbb9 }


condition:
	$a0
}