rule Win_Spyware_ye_162
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9f6da97ebad98c3e600db01abadf97 }


condition:
	$a0
}