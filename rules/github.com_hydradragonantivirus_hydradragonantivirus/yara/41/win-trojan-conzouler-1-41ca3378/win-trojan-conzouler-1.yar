rule Win_Trojan_Conzouler_1
{
strings:
	$a0 = { 0300cd2090b87742cd217344b44abbffffcd21b44a83eb1290cd21b448bb1100cd212d10008ec0bf03018bf48b3483 }


condition:
	$a0
}