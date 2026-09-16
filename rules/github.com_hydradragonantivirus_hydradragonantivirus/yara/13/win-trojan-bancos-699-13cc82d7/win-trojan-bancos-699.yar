rule Win_Trojan_Bancos_699
{
strings:
	$a0 = { cca368a5a0da85a488f9f50cf345b5c0a8e5a49978b7e30c80e485e78f32b99d5854691e41d7849b8215174a0d3b9ad3d0b7995635ad2ca887419bdd3bb6f0afddfdf6ff909defcf2e7f3bfd }


condition:
	$a0
}