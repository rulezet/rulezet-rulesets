rule Win_Trojan_Marauder_2
{
strings:
	$a0 = { 8bee81c643018bfefcad33861901abe2f88bf5 }


condition:
	$a0
}