rule Win_Trojan_Jihou_1
{
strings:
	$a0 = { ca83ef04890d894502b8004233c933d2cd21b0e9884501 }


condition:
	$a0
}