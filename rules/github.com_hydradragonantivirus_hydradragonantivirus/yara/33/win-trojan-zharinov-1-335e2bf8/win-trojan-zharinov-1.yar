rule Win_Trojan_Zharinov_1
{
strings:
	$a0 = { 8ed9bc007c8ed1fc8bdcb801028ec041ba8000cd13721b26813f33c97414b80103b10650cd13588bf48bfbb1dff3a541cd13b820008ec0b0538bf8be537c }


condition:
	$a0
}