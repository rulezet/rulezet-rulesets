rule Win_Trojan_MutatingInterrupt_1
{
strings:
	$a0 = { e800005e81ee0c018beebea5012e8ab60501b9160203f52e8a2432e62e882446e2f5bea501 }


condition:
	$a0
}