rule Win_Trojan_VGEN_110
{
strings:
	$a0 = { 1e06e8ac015025f0ff058a04c1e8048ccb03c38ed858c1e80403c38ec08cc82b0610005003060e00a31600a10c00a3 }


condition:
	$a0
}