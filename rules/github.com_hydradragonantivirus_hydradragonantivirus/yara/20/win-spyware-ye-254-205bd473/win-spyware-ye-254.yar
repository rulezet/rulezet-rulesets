rule Win_Spyware_ye_254
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]fbc105d216bde8923c610cfea6c3f3 }


condition:
	$a0
}