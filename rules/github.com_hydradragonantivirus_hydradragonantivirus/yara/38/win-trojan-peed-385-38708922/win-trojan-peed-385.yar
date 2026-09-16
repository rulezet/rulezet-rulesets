rule Win_Trojan_Peed_385
{
strings:
	$a0 = { 8d0438054ecd00003d4ecd0000740f3d24ab00007f086a006a006a00eb6de80c }


condition:
	$a0
}