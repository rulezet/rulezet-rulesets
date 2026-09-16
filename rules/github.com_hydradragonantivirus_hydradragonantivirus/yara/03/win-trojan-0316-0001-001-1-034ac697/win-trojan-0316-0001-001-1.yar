rule Win_Trojan__0316_0001_001_1
{
strings:
	$a0 = { 4233c933d2cd21b440b90300ba2cfbcd21b801572e8b16cafa2e8b0ec8fa80e1e080c903cd }


condition:
	$a0
}