rule Win_Trojan_Xboot_1
{
strings:
	$a0 = { 7cf7f34848900106497c83164b7c00bb007e8b16527ca1497ce89200721db002e8ac00eb76 }


condition:
	$a0
}