rule Win_Downloader_Small_2050
{
strings:
	$a0 = { 72726f78831c68748ff33a2f885f32317438182e6a756a636feb499ff30a106d2f628b3a50 }


condition:
	$a0
}