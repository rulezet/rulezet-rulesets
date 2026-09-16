rule Win_Trojan_Peed_55
{
strings:
	$a0 = { 8b6c041c83ed7883c51981c5fcfeffff83c0ff81eda000000085ed75edbf }


condition:
	$a0
}