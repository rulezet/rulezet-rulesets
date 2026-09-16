rule Win_Trojan_I_am_1
{
strings:
	$a0 = { dd4dca5be4bf0b7548d47aa5f43c30d528742107a22670c22f4ce2efeeef811d7eedc3863bcc023c }


condition:
	$a0
}