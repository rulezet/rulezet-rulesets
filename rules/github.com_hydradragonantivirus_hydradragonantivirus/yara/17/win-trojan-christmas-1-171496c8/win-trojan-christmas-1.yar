rule Win_Trojan_Christmas_1
{
strings:
	$a0 = { 07560a0359002a000ee80000fa8bec5832c08946028346002890b9ce05b08c8846ff8b5e00884efe8a4eff }


condition:
	$a0
}