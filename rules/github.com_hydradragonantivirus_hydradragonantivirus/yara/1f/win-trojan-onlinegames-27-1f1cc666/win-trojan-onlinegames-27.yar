rule Win_Trojan_Onlinegames_27
{
strings:
	$a0 = { 1bc2f9733d0bc7662bc09074069c7ebfe1865e }


condition:
	$a0
}