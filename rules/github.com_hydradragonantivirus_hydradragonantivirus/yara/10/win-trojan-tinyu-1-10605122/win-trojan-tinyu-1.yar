rule Win_Trojan_Tinyu_1
{
strings:
	$a0 = { 4b75635053521e06b8023d }


condition:
	$a0
}