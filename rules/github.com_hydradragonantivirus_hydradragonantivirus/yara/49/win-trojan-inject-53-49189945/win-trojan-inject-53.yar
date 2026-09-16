rule Win_Trojan_Inject_53
{
strings:
	$a0 = { 6801504000e801000000c3c3e2d8ec7b55f497e43784791152df814e680b30f6aade8f28ff9fc97d65 }


condition:
	$a0
}