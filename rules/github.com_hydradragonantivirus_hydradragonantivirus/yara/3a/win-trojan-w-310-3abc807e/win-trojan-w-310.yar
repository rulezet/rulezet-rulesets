rule Win_Trojan_W_310
{
strings:
	$a0 = { af751299b442ff166156f3a55eafabb510b440ff16b43eff16c961e9 }


condition:
	$a0
}