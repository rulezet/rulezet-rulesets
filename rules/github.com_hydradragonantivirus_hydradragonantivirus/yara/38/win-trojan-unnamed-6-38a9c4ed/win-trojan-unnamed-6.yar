rule Win_Trojan_Unnamed_6
{
strings:
	$a0 = { 70eb00e4713c0958740e5390bb0108f8b803c1cd215b7307581f07e881ffcb }


condition:
	$a0
}