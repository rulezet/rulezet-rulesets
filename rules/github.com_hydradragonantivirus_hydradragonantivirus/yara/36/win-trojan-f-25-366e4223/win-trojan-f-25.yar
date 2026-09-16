rule Win_Trojan_F_25
{
strings:
	$a0 = { b44033d2cd21b80042e8c300ba48028bf2c604e9582c03894401b440b90300cd21e98200 }


condition:
	$a0
}