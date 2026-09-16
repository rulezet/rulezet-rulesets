rule Win_Trojan_C_28
{
strings:
	$a0 = { 0e1fe800005d81ed0700b42fcd2106530e078d963f01b41acd218db631018dbe290166a566a5b44e33c98d963901 }


condition:
	$a0
}