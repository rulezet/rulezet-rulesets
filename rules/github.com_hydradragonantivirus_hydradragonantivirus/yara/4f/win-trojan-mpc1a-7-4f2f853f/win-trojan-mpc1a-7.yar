rule Win_Trojan_MPC1a_7
{
strings:
	$a0 = { e800005d81ed170181fc4144740b8db68601bf000157a4eb111e060e1f0e078db68d018dbe8501a5 }


condition:
	$a0
}