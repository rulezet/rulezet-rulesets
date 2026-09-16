rule Win_Trojan_Light_5
{
strings:
	$a0 = { dffa8ed7be007c8bde8be6fbff0e1304cd12b90602d3e08ec0b825000650f3a4cbfabea1002ec60490893670 }


condition:
	$a0
}