rule Win_Trojan_Crash_2
{
strings:
	$a0 = { fea6f00bf2190657e86ac6d3feb5f58069e9b2fe0380f0463da061bf960479e15ab323e0c5 }


condition:
	$a0
}