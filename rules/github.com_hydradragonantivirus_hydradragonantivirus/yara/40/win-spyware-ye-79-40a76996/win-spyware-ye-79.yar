rule Win_Spyware_ye_79
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4c9256a3670eb9e38d325d4f771c54 }


condition:
	$a0
}