rule Win_Trojan_Haxdoor_106
{
strings:
	$a0 = { 56f8c600713023f0c33cc4b207a2c021818a24ebc39cd0b9824ceae0a2357c006f4fb7aeb237503e1d0998cc1f95c0be1ad3c6588e00474bdcd79281a569e82e0060e1c8 }


condition:
	$a0
}