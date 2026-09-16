rule Win_Trojan_Mabuhay_3
{
strings:
	$a0 = { cd2180fcef73153d5b027510b4ffbf0001be0b01061f8b0e0400cd218cc88ed0bc850afceb }


condition:
	$a0
}