rule Win_Spyware_Banker_2095
{
strings:
	$a0 = { 2a9d104aa7ca5dbc13d8a60d56ca72c57e4b116d432706b8b54998936ee1188d56f0fe656d7a7edb877d61bef54f0b6dac9cd25c1b276c5ae38133b6cf722ef328e9720dc5d3d359b772ac5f72d1 }


condition:
	$a0
}