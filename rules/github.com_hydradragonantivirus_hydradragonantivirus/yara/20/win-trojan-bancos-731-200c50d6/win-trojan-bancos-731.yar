rule Win_Trojan_Bancos_731
{
strings:
	$a0 = { e6d8396a27baca057df724d55631f75a5e36b16666cfeb101a1b6a0ce40f9772634c770589b7562b0b73eadd00af89fa850e8d0b3ec902c69c95545ab14efa661ad7abe7a5b635df9f0e8064 }


condition:
	$a0
}