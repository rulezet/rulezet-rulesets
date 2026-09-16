rule Win_Trojan_VGEN_59
{
strings:
	$a0 = { 2e01064c008cdabb24008ec333ff8bf78ed8b97e00fcf3a5ea200024008edbbe7405bf3c01ad3d4e00740baba5 }


condition:
	$a0
}