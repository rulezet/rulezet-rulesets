rule Win_Trojan_Sirius_42
{
strings:
	$a0 = { 47484343e2f859af484715c6a55248594eff49bdf202118a5eff7b77f78d4f8a69c6b68d4f331acb900fc69fcb694b }


condition:
	$a0
}