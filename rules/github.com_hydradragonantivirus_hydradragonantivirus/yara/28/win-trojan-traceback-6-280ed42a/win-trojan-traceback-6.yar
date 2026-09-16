rule Win_Trojan_Traceback_6
{
strings:
	$a0 = { 19cd2189b4510181845101b4088c8c }


condition:
	$a0
}