rule Win_Trojan_Sahra_1
{
strings:
	$a0 = { 6800204000c32bc050e800000000ff253040400000000000 }


condition:
	$a0
}