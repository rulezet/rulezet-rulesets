rule Win_Trojan_Pakes_998
{
strings:
	$a0 = { 6033c0056c6c0000500509fd2d645005fe0f40ff508bc46a006a0050e8c7ffff }


condition:
	$a0
}