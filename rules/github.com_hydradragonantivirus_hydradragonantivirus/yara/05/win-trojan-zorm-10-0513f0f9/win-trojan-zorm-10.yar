rule Win_Trojan_Zorm_10
{
strings:
	$a0 = { 3802b90901f3a48db64302b9f800b010e86e00b4408d963802b90901cd21b8004233c999cd21b4 }


condition:
	$a0
}