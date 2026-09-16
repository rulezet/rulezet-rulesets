rule Win_Trojan_RiotRedMer_1
{
strings:
	$a0 = { 01faba4559cd16e800005d81ed0d018bc5051a0150eb1deb2d0000e81600b937038d56008b865304fec403d0b440cd21e80100c38b861c018db64901b9 }


condition:
	$a0
}