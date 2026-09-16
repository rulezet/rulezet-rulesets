rule Win_Trojan_Delf_2277
{
strings:
	$a0 = { 558becb83753c650bb81ed4e5950e800000000582da81a0000b96d1a0000ba211b }


condition:
	$a0
}