rule Win_Trojan_VGEN_4
{
strings:
	$a0 = { a2ed008ed8bb9f028cca871e4c0087164e000e1f871eae008716b000eb9633c0a3ec02e86bfe0e1f8a16ed0033 }


condition:
	$a0
}