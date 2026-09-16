rule Win_Trojan_Tv_1
{
strings:
	$a0 = { 5456743db440b9500190ba0002cd218bd6c605e980fe0075118ac224803c007509fecafecab6 }


condition:
	$a0
}