rule Win_Trojan_Gen_181
{
strings:
	$a0 = { b802009acd02340083ec02bf2c010e57b83f0050bf641e1e579a00002c00bf52001e57bf821e1e }


condition:
	$a0
}