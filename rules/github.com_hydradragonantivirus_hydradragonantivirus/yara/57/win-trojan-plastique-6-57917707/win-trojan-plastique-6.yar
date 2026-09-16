rule Win_Trojan_Plastique_6
{
strings:
	$a0 = { 618b1e4b00ff064b0083fb587503eb36 }


condition:
	$a0
}