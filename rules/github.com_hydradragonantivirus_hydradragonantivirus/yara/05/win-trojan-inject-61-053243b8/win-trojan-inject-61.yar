rule Win_Trojan_Inject_61
{
strings:
	$a0 = { 558bec8bc58bddf7d34381e3ff00000053e8fc000000e8 }


condition:
	$a0
}