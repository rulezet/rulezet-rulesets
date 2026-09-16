rule Win_Dropper_Agent_34722
{
strings:
	$a0 = { 60bbc87e7114c1cf04c1c70766bf64e1c1e3084b683a10400033ff81e1ee54d01687fac30fb6debe664f2c }


condition:
	$a0
}