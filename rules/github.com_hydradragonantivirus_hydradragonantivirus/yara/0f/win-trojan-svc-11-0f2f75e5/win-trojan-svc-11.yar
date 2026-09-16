rule Win_Trojan_SVC_11
{
strings:
	$a0 = { 560686c025ffff8ec00e1f33ffb9990bfcf3a6075e7403e9 }


condition:
	$a0
}