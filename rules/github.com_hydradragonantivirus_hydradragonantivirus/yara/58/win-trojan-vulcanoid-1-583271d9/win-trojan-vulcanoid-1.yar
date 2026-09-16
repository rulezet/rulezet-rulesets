rule Win_Trojan_Vulcanoid_1
{
strings:
	$a0 = { 8801833e5403027203e97e0131c0a3681031c0a36a10bf54011e578dbe00ff165731c0509aea07 }


condition:
	$a0
}