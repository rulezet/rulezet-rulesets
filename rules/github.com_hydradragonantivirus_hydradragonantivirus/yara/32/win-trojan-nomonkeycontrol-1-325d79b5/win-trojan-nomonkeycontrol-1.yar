rule Win_Trojan_NoMonkeyControl_1
{
strings:
	$a0 = { fdad50e2fc545805140050fac34c4c5dfbfc8c8e80 }


condition:
	$a0
}