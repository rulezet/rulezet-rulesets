rule Win_Trojan_Peed_196
{
strings:
	$a0 = { e8510000005589e55189e68b5d188d63045089f4e2f3592b55082b550c035510 }


condition:
	$a0
}