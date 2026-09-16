rule Win_Trojan_B_99
{
strings:
	$a0 = { 8edfbe1304ff0cadc1e006be007c1e561e56b99400518ec0f3a550686000cbbe4c005fa5c7 }


condition:
	$a0
}