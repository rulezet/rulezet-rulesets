rule Win_Trojan_Monday_2
{
strings:
	$a0 = { 080055e34300080009000203000083030000060000000203 }


condition:
	$a0
}