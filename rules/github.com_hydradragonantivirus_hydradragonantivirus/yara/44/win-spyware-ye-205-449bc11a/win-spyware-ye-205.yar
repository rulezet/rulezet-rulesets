rule Win_Spyware_ye_205
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ca10d421e58c3f690bb0d3c5ed8a3a }


condition:
	$a0
}