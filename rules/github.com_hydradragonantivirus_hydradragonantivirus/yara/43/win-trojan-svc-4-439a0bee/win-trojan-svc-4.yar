rule Win_Trojan_SVC_4
{
strings:
	$a0 = { 0686e035ffff8ec00e1f33ffb9a20bfcf3a6075e7403e9 }


condition:
	$a0
}