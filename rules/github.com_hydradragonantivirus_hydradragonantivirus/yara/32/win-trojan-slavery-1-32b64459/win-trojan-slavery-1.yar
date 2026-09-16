rule Win_Trojan_Slavery_1
{
strings:
	$a0 = { bf000081c70001b200be630403f7b447cd21b200be220403f7b447cd21b45c88a5210488a56204baa10303d7b41acd21 }


condition:
	$a0
}