rule Win_Trojan_Marauder_3
{
strings:
	$a0 = { c662048bfefdad33861901ab }


condition:
	$a0
}