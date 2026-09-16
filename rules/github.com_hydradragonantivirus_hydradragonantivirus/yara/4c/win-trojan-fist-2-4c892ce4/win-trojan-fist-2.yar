rule Win_Trojan_Fist_2
{
strings:
	$a0 = { 4d008a160701e82c00e93600e81200b4408bd583ea0390b9700290cd21e80100c3 }


condition:
	$a0
}