rule Win_Trojan_Anti_15
{
strings:
	$a0 = { c606480100b42acd2181f9c407720c81fa1108eb0690 }


condition:
	$a0
}