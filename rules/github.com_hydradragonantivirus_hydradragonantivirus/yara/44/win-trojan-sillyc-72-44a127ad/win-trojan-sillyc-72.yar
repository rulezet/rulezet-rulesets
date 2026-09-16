rule Win_Trojan_SillyC_72
{
strings:
	$a0 = { 2e8b36010181c6fa008bdebf0001fcb90300f3a48bd68bfb81c7af00b9000133f657f3a453b44eb94000cd213d0200 }


condition:
	$a0
}