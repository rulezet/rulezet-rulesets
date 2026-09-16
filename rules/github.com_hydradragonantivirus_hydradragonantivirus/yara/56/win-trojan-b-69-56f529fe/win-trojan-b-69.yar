rule Win_Trojan_B_69
{
strings:
	$a0 = { bc00f0fba11304b106d3e08ec0b80002 }


condition:
	$a0
}