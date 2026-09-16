rule anti_debug__PEB_IsDebugged__2___8_byt_11_
{
strings:
	$a0 = { 64a1300000008b400285c0 }

condition:
	$a0
}