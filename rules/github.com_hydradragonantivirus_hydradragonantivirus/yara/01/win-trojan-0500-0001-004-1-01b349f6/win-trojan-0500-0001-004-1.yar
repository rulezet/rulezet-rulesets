rule Win_Trojan__0500_0001_004_1
{
strings:
	$a0 = { 21b4408bf783c6fc81040001b902008bd6cd218b042d080181c62cff568904b440b902008bd6cd }


condition:
	$a0
}