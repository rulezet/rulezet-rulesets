rule Win_Trojan_Harmless_1
{
strings:
	$a0 = { 743bb9f1002e890c3dbc4a7430b913012e894c023d }


condition:
	$a0
}