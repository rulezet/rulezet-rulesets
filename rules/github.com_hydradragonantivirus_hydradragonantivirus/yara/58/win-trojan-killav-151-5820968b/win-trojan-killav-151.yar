rule Win_Trojan_Killav_151
{
strings:
	$a0 = { b87c664000baf0424000e811f7ffffb880664000ba00434000e802f7ffffa17c664000e898f8ffff8bd0b86c664000e818feffff }


condition:
	$a0
}