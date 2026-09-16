rule Win_Trojan_Bancos_1804
{
strings:
	$a0 = { a41fb1bf14aee13450c2c0dfb8f2e696f3664ce666616a7b0fbbfe5582d4320ac18ef3feec9e32ec2301184544ac7d7eb6ad3d31a0a9c90e45498fa38593e74e6593dbcae832 }


condition:
	$a0
}