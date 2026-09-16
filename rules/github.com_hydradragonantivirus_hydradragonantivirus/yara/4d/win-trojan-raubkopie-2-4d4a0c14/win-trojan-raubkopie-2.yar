rule Win_Trojan_Raubkopie_2
{
strings:
	$a0 = { 0132c0b43dcd2172068bd8b43ecd21 }


condition:
	$a0
}