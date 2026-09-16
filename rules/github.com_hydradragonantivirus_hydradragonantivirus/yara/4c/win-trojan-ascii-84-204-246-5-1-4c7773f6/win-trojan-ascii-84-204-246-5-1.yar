rule Win_Trojan_Ascii_84_204_246_5_1
{
strings:
	$a0 = { 38342e3230342e3234362e35 }


condition:
	$a0
}