rule Win_Trojan_Marl_1
{
strings:
	$a0 = { 8bfefcad33861901ab49e302ebf5 }


condition:
	$a0
}