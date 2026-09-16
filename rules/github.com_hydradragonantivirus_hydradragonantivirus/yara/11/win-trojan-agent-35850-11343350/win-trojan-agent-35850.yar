rule Win_Trojan_Agent_35850
{
strings:
	$a0 = { 654458781b5c42686b454d5b4049407d }

	$a1 = { 73696e6f6b697069 }

	$a2 = { 776f6b6963657961 }


condition:
	$a0 and $a1 and $a2
}