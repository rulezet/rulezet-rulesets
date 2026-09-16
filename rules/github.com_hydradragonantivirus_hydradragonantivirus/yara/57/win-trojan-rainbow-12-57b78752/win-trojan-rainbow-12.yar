rule Win_Trojan_Rainbow_12
{
strings:
	$a0 = { e800005e83ee03b8ad1bcd133dedde }


condition:
	$a0
}