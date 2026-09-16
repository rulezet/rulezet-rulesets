rule Win_Trojan_DarkApoc_1
{
strings:
	$a0 = { 8d8601058be0e800005d81ed09001e060e1f0e07fc8db6e8038dbeb204b90f00f3a48db6d4038dbef803b90400f3a5b42acd213c01752880fa107523b419cd21 }


condition:
	$a0
}