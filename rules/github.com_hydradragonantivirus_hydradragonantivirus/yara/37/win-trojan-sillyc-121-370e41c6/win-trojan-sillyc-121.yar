rule Win_Trojan_SillyC_121
{
strings:
	$a0 = { 01bee804b90300f3a48bfe83ef03ba00ffb41acd21b44e33c98bd6cd2172488bf783c603ba1effb8023dcd218bd8 }


condition:
	$a0
}