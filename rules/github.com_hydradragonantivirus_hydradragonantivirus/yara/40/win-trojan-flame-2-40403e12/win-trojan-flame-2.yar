rule Win_Trojan_Flame_2
{
strings:
	$a0 = { 7f15fd7408807f15f97519b10e890e0b02fec5cd60720db80103bb0002b9010032f6cd60071f61 }


condition:
	$a0
}