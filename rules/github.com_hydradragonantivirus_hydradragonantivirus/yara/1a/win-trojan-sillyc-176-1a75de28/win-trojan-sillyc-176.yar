rule Win_Trojan_SillyC_176
{
strings:
	$a0 = { 8becff264702c78cc381c31010068ec3bf0200be0001b94b01f2a4b98a0007faff264902c7bc32015835fcea505ee2f8770f075ee650fceb31cb45e2fcd9 }


condition:
	$a0
}