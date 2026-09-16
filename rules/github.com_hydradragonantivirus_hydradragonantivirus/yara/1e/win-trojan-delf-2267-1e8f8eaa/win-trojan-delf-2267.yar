rule Win_Trojan_Delf_2267
{
strings:
	$a0 = { 558bec83c4e85333c08945e88945ecb8743041 }


condition:
	$a0
}