rule Win_Trojan_VirusD_1
{
strings:
	$a0 = { 9d9c60565755061eb80043cd212e890e3003b8014333c9cd21b8023dcd218bd8b80057cd21 }


condition:
	$a0
}