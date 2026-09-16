rule Win_Trojan_Pakes_997
{
strings:
	$a0 = { 686c6c0000686f6e2e64687773686354 }


condition:
	$a0
}