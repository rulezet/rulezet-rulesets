rule Win_Trojan_VB_1030
{
strings:
	$a0 = { b85c0e50005064ff35000000006489250000000033c08908 }

	$a1 = { 57371b596726[0-18]4a6561576a67 }


condition:
	$a0 and $a1
}