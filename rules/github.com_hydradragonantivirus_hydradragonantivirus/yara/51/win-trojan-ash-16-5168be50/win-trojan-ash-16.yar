rule Win_Trojan_Ash_16
{
strings:
	$a0 = { b60501bf0001b90400fcf3a4b41a8d96c802cd21b44e8d }


condition:
	$a0
}