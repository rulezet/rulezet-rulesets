rule Win_Trojan_HtTM_1
{
strings:
	$a0 = { 50b8eb0458ebfbeaa703c150b8eb0458ebfbeae2e9 }


condition:
	$a0
}