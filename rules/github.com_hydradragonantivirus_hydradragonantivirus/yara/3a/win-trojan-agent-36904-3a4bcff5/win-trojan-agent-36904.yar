rule Win_Trojan_Agent_36904
{
strings:
	$a0 = { 4675636b }


condition:
	$a0
}