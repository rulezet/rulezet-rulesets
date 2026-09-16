rule Win_Spyware_ye_140
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]89579360a4c3f6a0c2ef9204acc9f9 }


condition:
	$a0
}