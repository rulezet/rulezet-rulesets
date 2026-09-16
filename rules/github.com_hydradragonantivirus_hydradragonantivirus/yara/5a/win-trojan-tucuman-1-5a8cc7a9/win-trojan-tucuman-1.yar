rule Win_Trojan_Tucuman_1
{
strings:
	$a0 = { 5d81ed0301b8004c8d9e14012ec707cd2190902ec70790908cc82e8b9e7e0603d82e2b9ed4052e899e7e06b8cd }


condition:
	$a0
}