rule Win_Trojan_AntiEta_1
{
strings:
	$a0 = { 32c55a2b7ea0f77481e30303a65490a79aef227dcd14e267e8b12a8209d4ac51981ad361c206feb7 }


condition:
	$a0
}