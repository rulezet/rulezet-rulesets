rule anti_debug__Detection_from_SafeDisc__this_is_the_content_of_secdrv_sys__8_byt_10_
{
strings:
	$a0 = { 0f21f825000500008901 }

condition:
	$a0
}