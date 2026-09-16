rule Win_Trojan_Trivial_332
{
strings:
	$a0 = { b409ba2801cd21b44eba3801b90700cd21b8023dba9e00cd2193b43ffec4ba0001b93e00cd21cd20 }


condition:
	$a0
}