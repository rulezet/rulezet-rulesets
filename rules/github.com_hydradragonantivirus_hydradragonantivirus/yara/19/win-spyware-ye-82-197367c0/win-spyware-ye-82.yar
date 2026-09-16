rule Win_Spyware_ye_82
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4f9d59ae6a09bcee903d604a6a0f47 }


condition:
	$a0
}