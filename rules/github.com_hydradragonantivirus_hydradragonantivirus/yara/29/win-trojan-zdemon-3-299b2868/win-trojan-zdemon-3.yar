rule Win_Trojan_Zdemon_3
{
strings:
	$a0 = { b74136b7744989d9541b8bf05c51019b988d7cc728dcff171d362d005a2d64656d306e20a594344e7253059c056a }


condition:
	$a0
}