rule Win_Trojan_DeadWin_1
{
strings:
	$a0 = { 022e8b3cf7d723faf7d22e21142e093cf7d24646e2eb }


condition:
	$a0
}