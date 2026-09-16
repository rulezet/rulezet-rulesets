rule Win_Trojan_Updown_1
{
strings:
	$a0 = { 2643108cc88ed8ba5400b425b01ccd }


condition:
	$a0
}