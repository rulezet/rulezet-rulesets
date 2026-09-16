rule Win_Dropper_Agent_31874
{
strings:
	$a0 = { e8af05000083c4046a016a006a008d8588faffff5068384140006a00ff15f8304000e950040000 }


condition:
	$a0
}