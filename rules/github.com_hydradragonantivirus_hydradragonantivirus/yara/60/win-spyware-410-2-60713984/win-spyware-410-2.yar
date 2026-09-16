rule Win_Spyware_410_2
{
strings:
	$a0 = { 109cf9e82d2b3cf12e84951535a02cc8cd2162ea506eca7ab74b84c45fda5c40f4fa7a4f8bcdfc31c2d555a84b0fbeeeedba0bf9fa4526c9c2a6e51be23bd6b61e73d7056582992319eebc018c59 }


condition:
	$a0
}