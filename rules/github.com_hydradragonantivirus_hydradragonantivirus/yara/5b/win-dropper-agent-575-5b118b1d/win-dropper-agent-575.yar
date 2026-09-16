rule Win_Dropper_Agent_575
{
strings:
	$a0 = { 81e0523e1a30e803????03??03 }

	$a1 = { 528a4c342348884c34244685c07feaeb3683f811750e6a038bcde886fbffff83c003eb0c6a078bcde878fbffff83c00b85c07e1381fef502 }


condition:
	$a0 and $a1
}