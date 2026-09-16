rule Win_Trojan_Deltree_36
{
strings:
	$a0 = { 2f7320756e6b6e6f776e2e72656720636c73 }

	$a1 = { 64656c74726565202f7920633a5c77696e646f77735c74656d705c2a2e2a }


condition:
	$a0 and $a1
}