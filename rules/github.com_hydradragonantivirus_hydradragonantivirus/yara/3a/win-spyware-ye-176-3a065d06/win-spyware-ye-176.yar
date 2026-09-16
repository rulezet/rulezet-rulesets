rule Win_Spyware_ye_176
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ad73b70cc8ef9accf69bc63050752d }


condition:
	$a0
}