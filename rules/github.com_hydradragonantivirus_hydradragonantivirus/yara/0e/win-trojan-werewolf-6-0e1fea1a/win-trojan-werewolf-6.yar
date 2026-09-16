rule Win_Trojan_WereWolf_6
{
strings:
	$a0 = { 2eb83511c2474781ffa20272f3c32ec606a70281ebe7 }


condition:
	$a0
}