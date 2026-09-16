rule Win_Trojan_Small_4425
{
strings:
	$a0 = { 68??2f42000f6e04240f7ec0bacae8ff }


condition:
	$a0
}