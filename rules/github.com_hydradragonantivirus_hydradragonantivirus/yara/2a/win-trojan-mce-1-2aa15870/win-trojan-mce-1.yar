rule Win_Trojan_MCE_1
{
strings:
	$a0 = { 459033ff8edffa8ed7be007c8bdec64402448be6ff0e1304cd12b90602d3e08ec0b82b000650f3a4cbbfaa00893e }


condition:
	$a0
}