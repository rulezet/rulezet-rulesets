rule Win_Trojan_Civil_1
{
strings:
	$a0 = { 80b600b90300b00cbb00002e8e061300b402cd132eff3613006a00cb }


condition:
	$a0
}