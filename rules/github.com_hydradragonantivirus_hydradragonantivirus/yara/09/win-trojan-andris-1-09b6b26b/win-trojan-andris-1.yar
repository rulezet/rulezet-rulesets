rule Win_Trojan_Andris_1
{
strings:
	$a0 = { 080126a3860026c7068400730126a3720026c7067000bd }


condition:
	$a0
}