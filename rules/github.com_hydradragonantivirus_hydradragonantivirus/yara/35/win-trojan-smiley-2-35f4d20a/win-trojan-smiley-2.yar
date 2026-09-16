rule Win_Trojan_Smiley_2
{
strings:
	$a0 = { 05018bc881e10f00d1e8d1e8d1e8d1e883f90074014089 }


condition:
	$a0
}