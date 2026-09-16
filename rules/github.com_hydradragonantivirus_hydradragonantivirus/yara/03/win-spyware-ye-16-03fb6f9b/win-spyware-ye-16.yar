rule Win_Spyware_ye_16
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0dd317ec284f7a2c567b269030550d }


condition:
	$a0
}