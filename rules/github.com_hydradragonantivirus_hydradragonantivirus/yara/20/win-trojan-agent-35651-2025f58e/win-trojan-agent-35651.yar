rule Win_Trojan_Agent_35651
{
strings:
	$a0 = { 50f956515253570f82b2feffff74c9bb270a1648 }

	$a1 = { 434c5349445c25315c50726f674944 }

	$a2 = { 636f6d2e72756e }


condition:
	$a0 and $a1 and $a2
}