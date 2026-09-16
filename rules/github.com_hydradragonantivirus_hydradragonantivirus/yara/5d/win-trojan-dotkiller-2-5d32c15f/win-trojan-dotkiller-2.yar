rule Win_Trojan_DotKiller_2
{
strings:
	$a0 = { 2ea30101582ea20001b80001ffe0b8 }


condition:
	$a0
}