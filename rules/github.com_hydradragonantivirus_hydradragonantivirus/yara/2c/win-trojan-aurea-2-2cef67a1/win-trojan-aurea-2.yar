rule Win_Trojan_Aurea_2
{
strings:
	$a0 = { bfb0c4a509a0b09b7804f03baebfb40a9eb47d91c3b95914b013a5b45bb72077b6a5b4b1b0049c7d }


condition:
	$a0
}