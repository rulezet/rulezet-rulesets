rule Win_Spyware_6647_1
{
strings:
	$a0 = { e8b80500000b976701c4895e81f3df27 }


condition:
	$a0
}