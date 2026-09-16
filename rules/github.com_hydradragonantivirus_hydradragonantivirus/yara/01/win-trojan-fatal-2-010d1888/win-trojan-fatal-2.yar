rule Win_Trojan_Fatal_2
{
strings:
	$a0 = { 793d3120746f2031206d7367626f782022617265 }

	$a1 = { 7365637572652220793d792b31 }

	$a2 = { 7a3d3120746f2035303030 }


condition:
	$a0 and $a1 and $a2
}