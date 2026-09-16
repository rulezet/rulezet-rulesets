rule Win_Trojan_Goma_21
{
strings:
	$a0 = { 81fa26fb777183fa0e726c81ead9033b96dd04746281c2d9038996da048d96dc04cd21e844 }


condition:
	$a0
}