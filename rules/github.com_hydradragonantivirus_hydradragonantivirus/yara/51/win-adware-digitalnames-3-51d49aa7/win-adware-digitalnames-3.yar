rule Win_Adware_Digitalnames_3
{
strings:
	$a0 = { 536f6674776172655c776e616d6573 }

	$a1 = { 6469676974616c6e616d6573 }

	$a2 = { 706c7567696e323030372f757064303031 }


condition:
	$a0 and $a1 and $a2
}