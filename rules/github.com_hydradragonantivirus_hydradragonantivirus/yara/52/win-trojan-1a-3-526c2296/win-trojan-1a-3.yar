rule Win_Trojan_1a_3
{
strings:
	$a0 = { 5d81ed160181fc2020740b8db6d301bf000157a4eb111e060e1f0e078db6d2018dbeca01a5 }


condition:
	$a0
}