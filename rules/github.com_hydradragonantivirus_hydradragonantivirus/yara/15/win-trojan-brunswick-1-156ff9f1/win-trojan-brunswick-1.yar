rule Win_Trojan_Brunswick_1
{
strings:
	$a0 = { ffe8e7ff74252ec606290100b80103 }


condition:
	$a0
}