rule Win_Trojan_Jonekey_1
{
strings:
	$a0 = { 568ccd83c5108db6030056be2d0056cb4d454d4f525924ba0000cd269dc3b8ffff8ed8ba0000e8d5ff }


condition:
	$a0
}