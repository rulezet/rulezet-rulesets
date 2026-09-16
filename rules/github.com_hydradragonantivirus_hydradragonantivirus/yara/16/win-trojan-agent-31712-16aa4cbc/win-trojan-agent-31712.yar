rule Win_Trojan_Agent_31712
{
strings:
	$a0 = { 68fc600010e8dafdffff566830610010e8cffdffff566860610010e8c4fdffff }


condition:
	$a0
}