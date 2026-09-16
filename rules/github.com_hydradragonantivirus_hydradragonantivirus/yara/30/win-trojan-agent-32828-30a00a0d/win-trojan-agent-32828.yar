rule Win_Trojan_Agent_32828
{
strings:
	$a0 = { 389416bed23d67c8027bde7cfaac8f92bccdc3bd1086e078942458fcfc0a3df63c9143c8b0033853032844837c9a70879a0e0dbfd7e4ff9784660e5a4e07b8f62b }


condition:
	$a0
}