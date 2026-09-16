rule Win_Trojan_VGEN_236
{
strings:
	$a0 = { 3abaf5d1f7e28bf0bbce738bce80e11fd3e38bebbb81d98bce80e11fd3eb31ddbbceff339c2611d1c3d1c38bcd }


condition:
	$a0
}