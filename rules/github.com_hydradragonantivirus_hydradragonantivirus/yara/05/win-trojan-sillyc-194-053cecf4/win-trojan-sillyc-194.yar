rule Win_Trojan_SillyC_194
{
strings:
	$a0 = { 40ba000103d7b98201cd21b8004233c933d2cd21b4408d951501b90100cd21b4408d950301 }


condition:
	$a0
}