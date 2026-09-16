rule Win_Trojan_W_317
{
strings:
	$a0 = { 99b442ff166156f3a55eabb510b440ff16b43eff16c961e96e }


condition:
	$a0
}