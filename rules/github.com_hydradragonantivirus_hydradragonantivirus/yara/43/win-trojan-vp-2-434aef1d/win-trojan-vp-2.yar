rule Win_Trojan_VP_2
{
strings:
	$a0 = { 731183c402802e280301803e280300 }


condition:
	$a0
}