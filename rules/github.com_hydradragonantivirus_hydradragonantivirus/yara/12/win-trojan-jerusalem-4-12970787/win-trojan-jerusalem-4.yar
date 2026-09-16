rule Win_Trojan_Jerusalem_4
{
strings:
	$a0 = { f004b440cd21e9e0002e8b1e04000e1fba4d00b91800b43fcd2172472ec7065f005a4d2ea15b }


condition:
	$a0
}