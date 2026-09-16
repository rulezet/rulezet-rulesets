rule Win_Trojan_SW_1
{
strings:
	$a0 = { c1ec00722b2d03002e8986de01b80040ba000101eab9ec00cd21b8004233c933d2cd21b80040ba }


condition:
	$a0
}