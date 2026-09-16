rule Win_Trojan_Small_1411
{
strings:
	$a0 = { 81eca40000005355565768483240006a }

	$a1 = { 7300005f5469004c5f4d75746578 }


condition:
	$a0 and $a1
}