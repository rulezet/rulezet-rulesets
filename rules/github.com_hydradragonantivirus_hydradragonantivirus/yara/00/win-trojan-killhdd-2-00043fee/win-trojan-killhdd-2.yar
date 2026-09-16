rule Win_Trojan_KillHDD_2
{
strings:
	$a0 = { b02fe670e67133db0e07b84003ba8000b90100cd13 }


condition:
	$a0
}