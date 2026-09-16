rule Win_Trojan_DVA_3
{
strings:
	$a0 = { 8bf281ee0301c35eeb2d90b42fcd218c840b03899c0d0333d28bd681c2df0181c200100e1fb41acd2189940903c3 }


condition:
	$a0
}