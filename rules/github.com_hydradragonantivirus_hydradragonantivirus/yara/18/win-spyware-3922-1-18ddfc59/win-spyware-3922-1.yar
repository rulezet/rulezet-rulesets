rule Win_Spyware_3922_1
{
strings:
	$a0 = { 525283c404890c2481ea1b42b14c81c21b42b14c895424fc524149 }


condition:
	$a0
}