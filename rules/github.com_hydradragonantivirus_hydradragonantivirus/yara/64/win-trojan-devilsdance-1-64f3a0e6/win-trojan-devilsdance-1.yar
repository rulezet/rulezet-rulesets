rule Win_Trojan_DevilsDance_1
{
strings:
	$a0 = { ad03f3a426c706000003015e1e068cc048 }


condition:
	$a0
}