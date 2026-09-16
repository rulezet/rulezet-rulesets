rule Win_Trojan_Small_4406
{
strings:
	$a0 = { 56575355e852000000e81b000000e8df }


condition:
	$a0
}