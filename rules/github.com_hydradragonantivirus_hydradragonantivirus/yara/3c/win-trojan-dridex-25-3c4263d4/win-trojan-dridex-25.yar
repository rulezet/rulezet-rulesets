rule Win_Trojan_Dridex_25
{
strings:
	$a0 = { ca74a9e23d6bec377bcf6f77ed72a04d42676d48a962cb8baa6456f8801d0a07f07309ad544cb66feb37fc4cbabeb27e6417bd6c5dcf5f76a502896f7d797b723072b6 }


condition:
	$a0
}