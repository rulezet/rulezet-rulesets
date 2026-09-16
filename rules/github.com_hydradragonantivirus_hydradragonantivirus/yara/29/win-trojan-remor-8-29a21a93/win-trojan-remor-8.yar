rule Win_Trojan_Remor_8
{
strings:
	$a0 = { 04a31e04a12004a34304a05104a25204c606510400be5304bf6104b90d00f3a4a12c00a3 }


condition:
	$a0
}