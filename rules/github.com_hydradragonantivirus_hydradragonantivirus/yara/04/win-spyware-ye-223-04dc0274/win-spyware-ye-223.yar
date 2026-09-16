rule Win_Spyware_ye_223
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]dc22e633f79ec9f39dc2eddf872c64 }


condition:
	$a0
}