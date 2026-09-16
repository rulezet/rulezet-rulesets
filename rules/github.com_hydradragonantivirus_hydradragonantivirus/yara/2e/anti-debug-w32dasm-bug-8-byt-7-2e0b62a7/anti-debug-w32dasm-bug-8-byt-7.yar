rule anti_debug__W32Dasm_bug__8_byt_7_
{
strings:
	$a0 = { eb03909090ebf9 }

condition:
	$a0
}