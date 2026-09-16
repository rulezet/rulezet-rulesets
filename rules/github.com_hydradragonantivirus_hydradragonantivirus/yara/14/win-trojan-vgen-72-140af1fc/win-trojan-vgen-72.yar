rule Win_Trojan_VGEN_72
{
strings:
	$a0 = { a10301bebb068904b8ffffb93412cd213d3412751a2e803e3601007403e952012e8b0e23018ccbb8eefeba3412cd21 }


condition:
	$a0
}