rule Win_Trojan_DarkApocalypse_2
{
strings:
	$a0 = { 2acd213c01752880fa107523b419cd218d9ebb02b90100 }


condition:
	$a0
}