rule Win_Dropper_Agent_35654
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d }

	$a1 = { 8283a55c222d5c6b61 }

	$a2 = { 3f8e789f251b53696728 }

	$a3 = { 2b3839445c3f13 }


condition:
	$a0 and $a1 and $a2 and $a3
}