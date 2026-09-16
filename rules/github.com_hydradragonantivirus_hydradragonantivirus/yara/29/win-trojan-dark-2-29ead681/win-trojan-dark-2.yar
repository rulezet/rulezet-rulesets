rule Win_Trojan_Dark_2
{
strings:
	$a0 = { 058be0e800005d81ed09001e060e1f0e07fc8db6ef038dbeb904b90f0090f3a48db6db038dbeff03b90400f3a5 }


condition:
	$a0
}