rule Win_Trojan_Poppy_2
{
strings:
	$a0 = { 908bf2896c01eb07b91800badd0390b440e8d2fe595ab80157e8cafeb43ee8c5feb801435a }


condition:
	$a0
}