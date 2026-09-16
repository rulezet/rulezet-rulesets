rule Win_Dropper_Juntador_12
{
strings:
	$a0 = { 33c05568aa36400064ff30648920536a006a008b45fce849f3ffff5068b83640006a00e814feffff }


condition:
	$a0
}