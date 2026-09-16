rule anti_debug__Rose_s_TRAP__4__1___8_byt_14_
{
strings:
	$a0 = { 0f21f80d002000000f23f80f21f8 }

condition:
	$a0
}