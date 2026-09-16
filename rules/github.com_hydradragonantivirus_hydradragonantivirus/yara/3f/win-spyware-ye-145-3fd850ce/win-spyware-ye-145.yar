rule Win_Spyware_ye_145
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8e5c986da9c8f3a5cffca711b1d68e }


condition:
	$a0
}