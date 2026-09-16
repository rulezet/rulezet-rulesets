rule Win_Trojan_BAT_101
{
strings:
	$a0 = { 2a2e6e6c73 }

	$a1 = { 2a2e726f6d202f712064656c20633a5c77696e646f77735c73797374656d3332202a2e726567 }

	$a2 = { 2a2e72616d }


condition:
	$a0 and $a1 and $a2
}