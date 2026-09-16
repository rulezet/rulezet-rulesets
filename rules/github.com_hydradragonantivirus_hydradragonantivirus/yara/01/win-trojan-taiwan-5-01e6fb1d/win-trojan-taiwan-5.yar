rule Win_Trojan_Taiwan_5
{
strings:
	$a0 = { 218bd8b43fb9a502ba00f8cd21b442b0 }


condition:
	$a0
}