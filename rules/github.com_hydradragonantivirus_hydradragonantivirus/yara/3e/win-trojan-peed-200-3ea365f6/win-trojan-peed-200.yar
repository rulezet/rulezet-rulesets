rule Win_Trojan_Peed_200
{
strings:
	$a0 = { eb3781e94432bb006800763e815a01c2520fc102 }


condition:
	$a0
}