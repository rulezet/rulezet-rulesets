rule Win_Spyware_ye_17
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0edc18ed294873254f7c279131560e }


condition:
	$a0
}