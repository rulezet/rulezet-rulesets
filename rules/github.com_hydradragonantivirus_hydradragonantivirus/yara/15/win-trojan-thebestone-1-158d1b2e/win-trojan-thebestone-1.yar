rule Win_Trojan_TheBestOne_1
{
strings:
	$a0 = { 2300e82d037303eb76902ea123000510008ed8e84303e82603b44abb010583c30fd1ebd1ebd1ebd1eb83c3102e }


condition:
	$a0
}