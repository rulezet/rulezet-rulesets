rule Win_Trojan_Rider_6
{
strings:
	$a0 = { e800005d81ed0701e81302d4ec195fe25e5ec5c58a45658d7266e5ff2f68d877e3f93572bf52c03b45bef5ef907ab15c }


condition:
	$a0
}