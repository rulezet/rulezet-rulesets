rule Win_Trojan_B_26
{
strings:
	$a0 = { bcfefffbb803028ec6bb007eb90200ba8000cd13ba00f8ea3e01b007ba04f9b462cd214b8edb }


condition:
	$a0
}