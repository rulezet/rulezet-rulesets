rule Win_Trojan_Violetta_2
{
strings:
	$a0 = { b021cd2189de061ffcad3d90907506ad3d909074390e1fb435b021cd21b0eaa20002891e01028c060302b425b0ff061f89dacd210e1fb425b021ba0003cd }


condition:
	$a0
}