rule Win_Trojan_Hong_1
{
strings:
	$a0 = { ea007c0000b90827ba0001cd1372f10e }


condition:
	$a0
}