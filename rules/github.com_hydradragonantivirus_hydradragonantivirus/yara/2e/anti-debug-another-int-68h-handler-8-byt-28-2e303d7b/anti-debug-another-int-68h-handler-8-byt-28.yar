rule anti_debug__another_INT_68h_handler__8_byt_28_
{
strings:
	$a0 = { 6631c08ec026668b1da0010000268e05a2010000b880fc430f263b03 }

condition:
	$a0
}