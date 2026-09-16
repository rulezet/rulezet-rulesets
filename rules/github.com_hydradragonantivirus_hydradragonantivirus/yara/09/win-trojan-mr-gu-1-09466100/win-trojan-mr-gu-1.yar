rule Win_Trojan_Mr_Gu_1
{
strings:
	$a0 = { 8db66301bf0001fcb90500f3a4b89392cd213d55477444b82135cd213e899eff028cc33e899e01031e0e5e4e8e }


condition:
	$a0
}