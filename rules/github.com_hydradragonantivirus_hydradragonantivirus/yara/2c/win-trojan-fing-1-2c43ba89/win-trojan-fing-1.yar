rule Win_Trojan_Fing_1
{
strings:
	$a0 = { feffcd213d15087503e95b01bf0001 }


condition:
	$a0
}