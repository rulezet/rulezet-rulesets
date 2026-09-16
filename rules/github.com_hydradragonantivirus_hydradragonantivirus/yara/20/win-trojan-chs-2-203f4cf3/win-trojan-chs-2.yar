rule Win_Trojan_Chs_2
{
strings:
	$a0 = { fe8bd00bc07503e98d0083fa03741b57b8950350b8520350b8480350b8a10250ff7606e865fe }


condition:
	$a0
}