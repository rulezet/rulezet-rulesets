rule Win_Trojan_WMA_5
{
strings:
	$a0 = { 8becb42acd218b6efa81ed0b01eb01002e8a9e1401bfb803908bcf8db62e012e301c46b42ecd21e0f6 }


condition:
	$a0
}