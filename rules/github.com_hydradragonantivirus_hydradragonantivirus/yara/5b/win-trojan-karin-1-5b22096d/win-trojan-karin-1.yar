rule Win_Trojan_Karin_1
{
strings:
	$a0 = { 53f3a4be00f8bf8000b98000f3a433ff33f633c033 }


condition:
	$a0
}