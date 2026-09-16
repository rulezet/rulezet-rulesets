rule Win_Trojan_Bancos_801
{
strings:
	$a0 = { 3b4d985de4b027da040fca9a362a0bd8cb5732e29b941ce75cde0f4d0ba6c32b406b43c0385ebb99ba547e0cfd30197ca32463d59253a37018ff6ab85187fc4afb5a2bcb7624a3a2200dd266b404ce9f99c6 }


condition:
	$a0
}