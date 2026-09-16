rule Win_Trojan_Deadman_2
{
strings:
	$a0 = { 950100b8024233c999cd21b440b91001908bd7cd2133c87514909090b8004299cd21b440b90a00 }


condition:
	$a0
}