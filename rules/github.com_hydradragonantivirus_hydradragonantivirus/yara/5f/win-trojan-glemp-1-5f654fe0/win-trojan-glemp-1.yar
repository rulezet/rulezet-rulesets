rule Win_Trojan_Glemp_1
{
strings:
	$a0 = { 023dcd218984ba00b900008bd18b9cba00b80242cd2189 }


condition:
	$a0
}