rule Win_Trojan_G2_8
{
strings:
	$a0 = { a5a58d96e302e838018db6a302b447b200cd218d9670 }


condition:
	$a0
}