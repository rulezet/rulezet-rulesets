rule Win_Trojan_Linc_3
{
strings:
	$a0 = { 01ba3e02c3e806009c2eff1e1802bdeefe2e80b61802 }


condition:
	$a0
}