rule Win_Trojan_GetLnk_1
{
strings:
	$a0 = { 670065005400200026004d0068002e006200410054 }


condition:
	$a0
}