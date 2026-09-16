rule Win_Trojan_SdBot_3627
{
strings:
	$a0 = { 2f118ff8c40d577c99ca3b5983854c2911d3732d33555cd93dc00a2d348d47ccc16685be806b960e91aa43f2cb3b13ba68e2fcf625cb9bfa09ea11cda8eb3b1a5fc6bab69971cfeb75020c7b2165 }


condition:
	$a0
}