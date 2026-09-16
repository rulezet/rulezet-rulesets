rule Win_Spyware_ye_248
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f53bffd410b7e2943e630ef8983d75 }


condition:
	$a0
}