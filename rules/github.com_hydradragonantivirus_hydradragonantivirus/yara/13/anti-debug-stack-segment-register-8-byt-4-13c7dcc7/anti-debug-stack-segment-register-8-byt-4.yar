rule anti_debug__Stack_Segment_register__8_byt_4_
{
strings:
	$a0 = { 16179c90 }

condition:
	$a0
}