rule Win_Dropper_Agent_34305
{
strings:
	$a0 = { 4156502e416c6572744469616c6f6700d3a6d3c3b5bdcbf9d3d000006a016a0068687340006a006a01e8dad1ffffa3bca640006a00 }


condition:
	$a0
}