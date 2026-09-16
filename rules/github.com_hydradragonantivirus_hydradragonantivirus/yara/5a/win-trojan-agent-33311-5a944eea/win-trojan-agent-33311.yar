rule Win_Trojan_Agent_33311
{
strings:
	$a0 = { 33ff8965f0894de06a0c897dfce8f00f00008bc883c404894de43bcfc645fc01740e68a4714000e8c60800008bd8eb0233db }


condition:
	$a0
}