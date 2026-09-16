rule Win_Trojan_R_76
{
strings:
	$a0 = { 1200e8c301061fb440b9ac0399cd210e1f33c0e86b01b440b90400ba9703cd21b801575a5980e1 }


condition:
	$a0
}