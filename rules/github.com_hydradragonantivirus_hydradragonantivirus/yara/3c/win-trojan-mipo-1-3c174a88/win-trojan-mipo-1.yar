rule Win_Trojan_Mipo_1
{
strings:
	$a0 = { b4428b1e490333c933d2b0029c2eff1ee200b4408b1e4903b9ff0390ba00009c2eff1ee2005e }


condition:
	$a0
}