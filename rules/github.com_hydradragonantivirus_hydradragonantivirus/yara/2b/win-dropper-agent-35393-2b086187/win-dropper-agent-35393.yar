rule Win_Dropper_Agent_35393
{
strings:
	$a0 = { 5c6d617472697833313939322e657865 }

	$a1 = { 655c766964656f736f6674 }

	$a2 = { 5c6d6f6465726e2d6865616465722e626d70 }


condition:
	$a0 and $a1 and $a2
}