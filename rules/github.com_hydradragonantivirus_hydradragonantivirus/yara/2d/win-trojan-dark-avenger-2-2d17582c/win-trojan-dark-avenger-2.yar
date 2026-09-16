rule Win_Trojan_Dark_Avenger_2
{
strings:
	$a0 = { b95407f3a433c08ed8c7068400ee028c }


condition:
	$a0
}