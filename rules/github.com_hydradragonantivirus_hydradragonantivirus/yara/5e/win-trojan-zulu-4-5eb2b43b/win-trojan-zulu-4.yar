rule Win_Trojan_Zulu_4
{
strings:
	$a0 = { 4b7403eb53902e8c161a012e89261c010e17bc0302 }


condition:
	$a0
}