rule Win_Trojan_Murphy_13
{
strings:
	$a0 = { fe33c0501fc4064c002e8984 }


condition:
	$a0
}