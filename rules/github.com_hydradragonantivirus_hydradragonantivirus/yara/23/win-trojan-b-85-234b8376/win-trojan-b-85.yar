rule Win_Trojan_B_85
{
strings:
	$a0 = { bc007c8ed3fb8edb832e130404b106cd12d3e0ba80 }


condition:
	$a0
}