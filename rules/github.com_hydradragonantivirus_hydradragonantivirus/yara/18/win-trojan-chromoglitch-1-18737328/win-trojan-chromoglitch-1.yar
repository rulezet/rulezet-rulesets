rule Win_Trojan_Chromoglitch_1
{
strings:
	$a0 = { b440cc3bc875c757c35e33c0e8c800b43fb91a008d96c202ccb43ecc81bed2024d4c74a2 }


condition:
	$a0
}