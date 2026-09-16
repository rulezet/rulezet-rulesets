rule Win_Trojan_Gen_178
{
strings:
	$a0 = { e6a77057b80157e47e060d8b5585ebaca9b0f4e005ff5f50f80998db08757774137ad15fd8 }


condition:
	$a0
}