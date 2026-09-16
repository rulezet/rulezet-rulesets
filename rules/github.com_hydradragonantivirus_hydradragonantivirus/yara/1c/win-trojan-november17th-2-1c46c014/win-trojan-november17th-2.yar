rule Win_Trojan_November17th_2
{
strings:
	$a0 = { ff803d5a75c28b45032d3800894503836d12384303c3 }


condition:
	$a0
}