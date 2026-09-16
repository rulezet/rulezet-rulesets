rule Win_Spyware_ye_119
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]74ba7e4b8f36610bb5da85771f447c }


condition:
	$a0
}