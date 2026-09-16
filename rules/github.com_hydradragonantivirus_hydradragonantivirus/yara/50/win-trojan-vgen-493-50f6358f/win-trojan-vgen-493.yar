rule Win_Trojan_VGEN_493
{
strings:
	$a0 = { 0b01c686100200b42fcd21538d961906b41acd21e817005ab41acd21bf0001578db60e028b34 }


condition:
	$a0
}