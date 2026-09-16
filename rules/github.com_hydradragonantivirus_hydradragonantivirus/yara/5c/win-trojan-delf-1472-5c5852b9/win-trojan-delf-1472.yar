rule Win_Trojan_Delf_1472
{
strings:
	$a0 = { 60e8000000008b2c2483c4048db54a02 }


condition:
	$a0
}