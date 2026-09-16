rule Win_Dropper_Agent_35447
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d10 }

	$a1 = { 53656c665570646174652e657865 }

	$a2 = { 54534550422e444154 }


condition:
	$a0 and $a1 and $a2
}