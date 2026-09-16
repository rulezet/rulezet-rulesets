rule Win_Trojan_ArchVir_2
{
strings:
	$a0 = { a000c80202006a00bf60021e5768ff009a5c09a0008dbe00ff1657bf60021e576a016a029a950ba000bf60011e }


condition:
	$a0
}