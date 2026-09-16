rule Win_Trojan_Mvf_2
{
strings:
	$a0 = { 0b428b85f545ab420b46094283071cc94e51a8430bc84e50a9420bf7f5cb6e4eb24326f83e51b33b5c8e2b7ee58e7f }


condition:
	$a0
}