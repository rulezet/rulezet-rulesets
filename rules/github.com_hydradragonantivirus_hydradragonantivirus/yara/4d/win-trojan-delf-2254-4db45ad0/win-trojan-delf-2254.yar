rule Win_Trojan_Delf_2254
{
strings:
	$a0 = { 558becb9210000006a006a004975f9b8a4640010e8dbbaffff33c05568d06f001064ff30648920 }


condition:
	$a0
}