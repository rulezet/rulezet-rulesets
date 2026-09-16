rule Win_Trojan_Tiny_96
{
strings:
	$a0 = { b413cd2f0e1fba15010653668f062101cd2f92cd2726803f4d75050e07bb0001ea }


condition:
	$a0
}