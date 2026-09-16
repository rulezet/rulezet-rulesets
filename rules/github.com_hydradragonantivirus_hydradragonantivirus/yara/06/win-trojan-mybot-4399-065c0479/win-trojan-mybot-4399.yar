rule Win_Trojan_Mybot_4399
{
strings:
	$a0 = { 4849454c44221f92cd6172905a496163323030e89bf74f33457cc9375163112cc58863 }


condition:
	$a0
}