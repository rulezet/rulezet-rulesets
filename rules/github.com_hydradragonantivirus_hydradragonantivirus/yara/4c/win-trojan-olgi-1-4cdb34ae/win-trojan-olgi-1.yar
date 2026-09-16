rule Win_Trojan_Olgi_1
{
strings:
	$a0 = { 8c86bf000e0e1f078db6b7008dbeaf00b90400fcf3a5b8124bcd213d34127502eb5f8b86bf00488ed8c6060000 }


condition:
	$a0
}