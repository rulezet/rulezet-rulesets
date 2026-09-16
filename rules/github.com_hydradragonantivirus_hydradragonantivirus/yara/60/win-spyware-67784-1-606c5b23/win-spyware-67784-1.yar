rule Win_Spyware_67784_1
{
strings:
	$a0 = { 0a494520436f6f6b696573[0-15]646c255053 }

	$a1 = { f166747761725c6d69356f0d5c696eb6 }

	$a2 = { f2504f5354d42d3d7d }

	$a3 = { 07d6268c }


condition:
	$a0 and $a1 and $a2 and $a3
}