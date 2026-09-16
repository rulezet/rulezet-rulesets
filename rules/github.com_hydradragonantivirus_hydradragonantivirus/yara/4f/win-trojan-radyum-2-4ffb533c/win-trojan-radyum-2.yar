rule Win_Trojan_Radyum_2
{
strings:
	$a0 = { e800005d81ed0801e80400eb2142238db633018bfeb9e300ad33861201abe2f8c3 }


condition:
	$a0
}