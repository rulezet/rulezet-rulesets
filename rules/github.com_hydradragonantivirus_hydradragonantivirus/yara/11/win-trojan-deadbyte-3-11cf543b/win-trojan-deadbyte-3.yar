rule Win_Trojan_DeadByte_3
{
strings:
	$a0 = { 61726a2061202d7920765f6f5f62652e61726a20765f6f5f62652e65786520 }


condition:
	$a0
}