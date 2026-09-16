rule Win_Trojan_Agent_34168
{
strings:
	$a0 = { 37e7b8ec11ccebb8 }


condition:
	$a0
}