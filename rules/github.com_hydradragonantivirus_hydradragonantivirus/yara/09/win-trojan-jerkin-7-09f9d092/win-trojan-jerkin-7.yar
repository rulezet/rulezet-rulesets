rule Win_Trojan_Jerkin_7
{
strings:
	$a0 = { 1b008d9e9a018b86f80131074343e2fa5bc3 }


condition:
	$a0
}