rule Win_Trojan_Netbus_7
{
strings:
	$a0 = { 776f7264206f6e204c555a414b5f2d7365727665723a0000ffffffff0800000050617373776f726400000000ffffffff }


condition:
	$a0
}