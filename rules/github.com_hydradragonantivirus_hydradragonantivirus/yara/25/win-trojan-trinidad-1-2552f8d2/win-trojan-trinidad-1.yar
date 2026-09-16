rule Win_Trojan_Trinidad_1
{
strings:
	$a0 = { e80f00e80d00e80b00e800005d81ed????c3c3c3[0-30]8db6????bf0001a5a4c3 }


condition:
	$a0
}