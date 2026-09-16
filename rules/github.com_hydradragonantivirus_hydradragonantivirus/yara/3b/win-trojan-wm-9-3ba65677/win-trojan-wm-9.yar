rule Win_Trojan_WM_9
{
strings:
	$a0 = { 020055a6110000000100470a00003903000004000000440a }


condition:
	$a0
}