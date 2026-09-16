rule Win_Trojan_Quiet_1
{
strings:
	$a0 = { 08030e9605ba0000b4408b1e9a051e8e1e9c05cd211fb449cd21c3bf0000 }


condition:
	$a0
}