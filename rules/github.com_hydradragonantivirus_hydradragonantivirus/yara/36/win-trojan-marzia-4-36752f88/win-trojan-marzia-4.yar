rule Win_Trojan_Marzia_4
{
strings:
	$a0 = { 7503eb6e901ebb4456b400cd131f3d4456740b8cd01e525017e8af035a1ffa8cd88ec02e030654000510008e }


condition:
	$a0
}