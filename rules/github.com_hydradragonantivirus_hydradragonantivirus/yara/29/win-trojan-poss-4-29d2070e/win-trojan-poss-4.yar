rule Win_Trojan_Poss_4
{
strings:
	$a0 = { 011f2e8b0e160a2e803e5b000b750481e98e0933d2 }


condition:
	$a0
}