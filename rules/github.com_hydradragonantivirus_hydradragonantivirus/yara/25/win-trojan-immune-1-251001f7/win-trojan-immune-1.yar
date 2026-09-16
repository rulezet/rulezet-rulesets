rule Win_Trojan_Immune_1
{
strings:
	$a0 = { ff1e2f0172782ea3e603b4ff32dbcd13b4409c2e8b1ee003b918020e1fba00012eff1e2f017257 }


condition:
	$a0
}