rule Win_Dropper_Agent_34564
{
strings:
	$a0 = { 87fe8ce68cdf8edeff351800000090909090 }


condition:
	$a0
}