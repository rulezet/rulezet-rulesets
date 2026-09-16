rule Win_Trojan_N_31
{
strings:
	$a0 = { 02eb4cb937058dbe6301ba010033c0eb0632e4cd1a92c3 }


condition:
	$a0
}