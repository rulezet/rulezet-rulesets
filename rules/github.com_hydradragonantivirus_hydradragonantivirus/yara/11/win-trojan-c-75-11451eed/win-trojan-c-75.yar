rule Win_Trojan_C_75
{
strings:
	$a0 = { 14cbb003cf9c3de0337505b802a59dcf3de133750d }


condition:
	$a0
}