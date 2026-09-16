rule Win_Trojan_Fack_2
{
strings:
	$a0 = { 01b440ba0001cd21b80042e8be00bf4a028bd6c604e95840894401c6440346b440b90400cd21 }


condition:
	$a0
}