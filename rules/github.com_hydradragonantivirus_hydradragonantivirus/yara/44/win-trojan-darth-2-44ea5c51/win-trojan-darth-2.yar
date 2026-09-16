rule Win_Trojan_Darth_2
{
strings:
	$a0 = { 90e800005b83eb06a3fe0033c08ed8c406ac0033ffb90010e84f0072392e89bf930033f6061fad3d2e8b74034eebf7ac3c9f74034eebf5ad938b8f800093 }


condition:
	$a0
}