rule Win_Trojan_Ginger_2
{
strings:
	$a0 = { b106d3e08ec0b80502bb0302b90300cd13 }


condition:
	$a0
}