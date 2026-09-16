rule Win_Trojan_B_103
{
strings:
	$a0 = { 26be017f060e07b8010333dbb90100e83a00072e800ebe0180be9801eb04 }


condition:
	$a0
}