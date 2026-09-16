rule Win_Trojan_Agent_36908
{
strings:
	$a0 = { 4675636b }


condition:
	$a0
}