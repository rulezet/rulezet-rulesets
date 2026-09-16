rule Win_Trojan_Sylvia_1
{
strings:
	$a0 = { cd21ebfec3a17002a3780233c0a39e02 }


condition:
	$a0
}