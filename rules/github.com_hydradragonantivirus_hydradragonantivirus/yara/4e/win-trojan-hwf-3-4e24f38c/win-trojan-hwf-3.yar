rule Win_Trojan_HWF_3
{
strings:
	$a0 = { 2a000e90901fb94a295185c381c13dda58700000077c00fcfa4348e2f6 }


condition:
	$a0
}