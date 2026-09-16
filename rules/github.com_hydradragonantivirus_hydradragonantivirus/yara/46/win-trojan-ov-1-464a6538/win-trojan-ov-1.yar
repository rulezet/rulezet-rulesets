rule Win_Trojan_OV_1
{
strings:
	$a0 = { 45040e57e89cfebf49040e57e894fe }


condition:
	$a0
}