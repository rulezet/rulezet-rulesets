rule Win_Trojan_Roohi_1
{
strings:
	$a0 = { 8c064e002e8c0e5000e8950181f966067470b44a2e8b1e42002e031e520083c3102e031e4400cd212eff3644002eff }


condition:
	$a0
}