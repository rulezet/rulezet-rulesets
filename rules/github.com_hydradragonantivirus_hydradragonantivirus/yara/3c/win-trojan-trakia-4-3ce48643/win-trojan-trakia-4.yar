rule Win_Trojan_Trakia_4
{
strings:
	$a0 = { d6772f5005b3fd3906470258742405fdffa3440233d2b94a0290b440cd2133c933d2b80042cd }


condition:
	$a0
}