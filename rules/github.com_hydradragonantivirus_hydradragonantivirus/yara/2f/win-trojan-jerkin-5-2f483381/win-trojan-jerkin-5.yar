rule Win_Trojan_Jerkin_5
{
strings:
	$a0 = { e90000e800005f81ef0900c6852500318befe80200eb12b9ba008d9e2c008b96b80190174343e2fac3 }


condition:
	$a0
}