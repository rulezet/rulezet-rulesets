rule Win_Trojan_Serg_1
{
strings:
	$a0 = { ba0000e800005d81edd101fae88901fbc686680390c686250200eb3f905c3f3f3f3f3f3f3f2e434f4d00303030303030 }


condition:
	$a0
}