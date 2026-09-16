rule Win_Trojan_JS_123
{
strings:
	$a0 = { 7768696c65202874727565292077696e646f772e616c65727428 }


condition:
	$a0
}