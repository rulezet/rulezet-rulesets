rule Win_Trojan_Suspect_5
{
strings:
	$a0 = { 652d636172642e68746d[0-60]2e6578655554 }


condition:
	$a0
}