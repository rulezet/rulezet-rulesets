rule Win_Trojan_WW_1
{
strings:
	$a0 = { ab009a380542005589e581ec02028dbe00ff165731c0509a940bab00bfce1b1e57b8ff00509a2b03ab00c606ce }


condition:
	$a0
}