rule Win_Trojan_Gen_35
{
strings:
	$a0 = { 8a4600a200018b4601a30101b8cc4bcd }


condition:
	$a0
}