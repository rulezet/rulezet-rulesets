rule Win_Trojan_Banker_6340
{
strings:
	$a0 = { 558bec83c4f0b828f34900e82c71f6ffa1c81e4a008b00e8 }

	$a1 = { 50726f7879506f7274 }

	$a2 = { 616c6578613154696d6572 }


condition:
	$a0 and $a1 and $a2
}