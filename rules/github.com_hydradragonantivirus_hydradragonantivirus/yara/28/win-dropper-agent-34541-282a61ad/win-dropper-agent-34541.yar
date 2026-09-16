rule Win_Dropper_Agent_34541
{
strings:
	$a0 = { fe81115c34506f726e00536f6674776172655c34506f726e00fd95805c556e69 }


condition:
	$a0
}