rule Win_Trojan_ARCV_7
{
strings:
	$a0 = { 0181fc4f50740b8db68601bf000157a4eb111e060e }


condition:
	$a0
}