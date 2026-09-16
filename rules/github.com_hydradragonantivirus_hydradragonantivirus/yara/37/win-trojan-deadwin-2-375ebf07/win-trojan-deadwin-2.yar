rule Win_Trojan_DeadWin_2
{
strings:
	$a0 = { 8b3cf7d723fdf7d52e212c2e093cf7d54646e2eb }


condition:
	$a0
}