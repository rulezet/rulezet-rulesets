rule Win_Trojan_Startpage_272
{
strings:
	$a0 = { 2756e6164612e636f6d000000ffffffff0300000053505900ffffffff0300000043414d00ffffffff25000000687474703a2f2f66726 }


condition:
	$a0
}