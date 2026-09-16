rule Win_Trojan_Susan_1
{
strings:
	$a0 = { c91fcd21b43ecd21c3505256571e068c }


condition:
	$a0
}