rule Win_Trojan_Mx_1
{
strings:
	$a0 = { 4b754a501e52065333c08ec026a16c042503003d0300 }


condition:
	$a0
}