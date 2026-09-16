rule Win_Trojan_Killfiles_55
{
strings:
	$a0 = { 657869737420633a5c77696e646f77735c2a2e646c6c2064656c20633a5c77696e646f77735c2a2e646c6c }


condition:
	$a0
}