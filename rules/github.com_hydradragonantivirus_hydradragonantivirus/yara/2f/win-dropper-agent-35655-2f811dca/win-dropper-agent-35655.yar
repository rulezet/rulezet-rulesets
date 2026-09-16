rule Win_Dropper_Agent_35655
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d10 }

	$a1 = { 3d3f32071b506e01f5d5 }

	$a2 = { 8a07767e2f40413e45 }

	$a3 = { 633a493e796e }


condition:
	$a0 and $a1 and $a2 and $a3
}