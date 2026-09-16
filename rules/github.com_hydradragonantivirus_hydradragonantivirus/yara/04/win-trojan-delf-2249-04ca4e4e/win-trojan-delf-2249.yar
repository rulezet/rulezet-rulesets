rule Win_Trojan_Delf_2249
{
strings:
	$a0 = { 558bec83c4f05356b87c894000e8033b0000b898 }

	$a1 = { 737663686f73742e657865 }

	$a2 = { 646f776e6c6f61646572 }


condition:
	$a0 and $a1 and $a2
}