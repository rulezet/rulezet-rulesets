rule Win_Trojan_Dumador_44
{
strings:
	$a0 = { 780c688f707370bb91ff12b7380b616284743a626c62616e6bb706edff0d0d5d5c6476702e6c6f674bb80145546ef0 }


condition:
	$a0
}