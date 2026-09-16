rule Win_Trojan_Mnemonix_6
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21[2-3]03cd27b44ccd21 }


condition:
	$a0
}