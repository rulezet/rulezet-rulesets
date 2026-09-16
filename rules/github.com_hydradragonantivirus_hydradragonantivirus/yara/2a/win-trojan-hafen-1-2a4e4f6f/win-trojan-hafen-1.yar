rule Win_Trojan_Hafen_1
{
strings:
	$a0 = { b305999907e8060159f684b705ff7502e2e7c326a12c }


condition:
	$a0
}