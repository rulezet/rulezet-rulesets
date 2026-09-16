rule Win_Trojan_Exorcist_2
{
strings:
	$a0 = { 21cd1980fa057f0bb8085fb200cd21b201cd215a2e8137 }


condition:
	$a0
}