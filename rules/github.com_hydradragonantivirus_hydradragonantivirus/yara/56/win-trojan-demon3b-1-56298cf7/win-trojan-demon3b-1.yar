rule Win_Trojan_Demon3b_1
{
strings:
	$a0 = { 2e8a1580c2dc80ea7580c24b80eac82e8815f7d7f7df81ff481075e4 }


condition:
	$a0
}