rule Win_Trojan_Equals_1
{
strings:
	$a0 = { 42b900002e8b1e4b009c2eff1e1200b440b9e804900e1f2e8b1e4b00ba00009c2eff1e1200 }


condition:
	$a0
}