rule Win_Trojan_Joker_6
{
strings:
	$a0 = { bf00018bf281c600018bcb2bcef3a458fa8e57fb8b67f9fb }


condition:
	$a0
}