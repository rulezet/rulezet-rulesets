rule Win_Spyware_ye_38
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]23e92dfa3e6510bae48934a6ceeb9b }


condition:
	$a0
}