rule Win_Trojan_Delf_2278
{
strings:
	$a0 = { 558bec83c4ec53565733c08945ecb8f04a5000e8 }

	$a1 = { 2f6c732e706870 }

	$a2 = { 364d79536f636b73 }


condition:
	$a0 and $a1 and $a2
}