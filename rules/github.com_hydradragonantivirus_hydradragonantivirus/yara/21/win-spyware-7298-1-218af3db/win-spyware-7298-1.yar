rule Win_Spyware_7298_1
{
strings:
	$a0 = { 60562bf65e03fe61e8100000005c202bc3 }


condition:
	$a0
}