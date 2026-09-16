rule Win_Trojan_Agent_34150
{
strings:
	$a0 = { c7842448feffff00e49609c7842420feffff4866d073 }


condition:
	$a0
}