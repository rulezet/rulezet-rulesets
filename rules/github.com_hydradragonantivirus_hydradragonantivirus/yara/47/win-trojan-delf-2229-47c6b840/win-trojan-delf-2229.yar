rule Win_Trojan_Delf_2229
{
strings:
	$a0 = { 8b55a0b8f8dc4500e83399faff8d459ce8839dfaff50a1a0dc4500508b00ff5078e8e2b0faff8b559cb8c0ac4500e8ad9ffaff }


condition:
	$a0
}