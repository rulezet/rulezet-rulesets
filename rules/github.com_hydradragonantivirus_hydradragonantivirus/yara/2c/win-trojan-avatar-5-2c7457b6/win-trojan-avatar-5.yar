rule Win_Trojan_Avatar_5
{
strings:
	$a0 = { 8db600002bffb98301f3a5061fb82125babd00cd2107b42acd213c01742481 }


condition:
	$a0
}