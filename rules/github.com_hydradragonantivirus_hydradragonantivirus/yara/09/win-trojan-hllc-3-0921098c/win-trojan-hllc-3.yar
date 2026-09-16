rule Win_Trojan_HLLC_3
{
strings:
	$a0 = { 0e024a012d0335240000060e1f8b0e0c008bf14e89f78cdb031e0a008ec3 }


condition:
	$a0
}