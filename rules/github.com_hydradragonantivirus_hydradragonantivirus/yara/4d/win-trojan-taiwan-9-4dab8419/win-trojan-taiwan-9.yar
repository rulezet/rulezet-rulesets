rule Win_Trojan_Taiwan_9
{
strings:
	$a0 = { 0b0033f6bb80008b00504646e2f9fe06 }


condition:
	$a0
}