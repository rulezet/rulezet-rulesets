rule Win_Trojan_Trojan_110
{
strings:
	$a0 = { 8e0190ba00e090cd21b43ecd21268b1e00e081fb009674 }


condition:
	$a0
}