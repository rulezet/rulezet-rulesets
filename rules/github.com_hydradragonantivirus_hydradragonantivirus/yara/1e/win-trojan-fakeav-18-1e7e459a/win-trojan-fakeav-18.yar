rule Win_Trojan_Fakeav_18
{
strings:
	$a0 = { 0743617074696f6e062a585020506f6c69636520416e74697669727573 }


condition:
	$a0
}