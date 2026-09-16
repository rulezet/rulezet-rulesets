rule Win_Trojan_Trivial_433
{
strings:
	$a0 = { e84f007504b44febf3cd20fab409ba3501cd21ebfe }


condition:
	$a0
}