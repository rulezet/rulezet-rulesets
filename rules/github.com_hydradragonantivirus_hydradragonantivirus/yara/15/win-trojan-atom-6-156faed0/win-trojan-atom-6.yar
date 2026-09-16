rule Win_Trojan_Atom_6
{
strings:
	$a0 = { 01040055a603000300040055050000eb000000040000005505 }


condition:
	$a0
}