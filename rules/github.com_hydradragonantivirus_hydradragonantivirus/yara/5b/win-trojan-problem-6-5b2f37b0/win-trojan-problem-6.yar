rule Win_Trojan_Problem_6
{
strings:
	$a0 = { a39000a386002b067d033dfb037440b002e8b90183fa037d3650a169033d4d5a742e3d5a4d }


condition:
	$a0
}