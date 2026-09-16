rule Win_Trojan_Mipo_2
{
strings:
	$a0 = { 428b1e970333c933d2b0029c2eff1e4601b4408b1e9703b96b0490ba00009c2eff1e46015e }


condition:
	$a0
}