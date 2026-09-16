rule Win_Trojan_Ginger_1
{
strings:
	$a0 = { b106d3e08ec0b80502bb0302b90300cd13b0e833fffcaa }


condition:
	$a0
}