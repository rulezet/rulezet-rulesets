rule Win_Trojan_DiskKiller_4
{
strings:
	$a0 = { d2f7361a0088163f01a34101c3a14101 }


condition:
	$a0
}