rule Win_Trojan_SatanBug_3
{
strings:
	$a0 = { 903e4dfcfc454a264a453e43f9f9f94d4b9e434526b98d004b43423ef5f8f8e80f0026f5fb2e42fc4afc42424df9 }


condition:
	$a0
}