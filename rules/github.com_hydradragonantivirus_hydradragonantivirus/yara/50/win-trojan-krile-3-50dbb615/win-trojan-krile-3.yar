rule Win_Trojan_Krile_3
{
strings:
	$a0 = { 01001aeb4ec3000000f31def82070101002a0568080100de102000de101c0400000e05d2a260a0247f44dd60df879c }


condition:
	$a0
}