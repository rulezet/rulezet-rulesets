rule Win_Trojan_Meditati_1
{
strings:
	$a0 = { 01813e2d01090874252bc951b800425acd21721a2e8b0e0f01b4402bd2cd21 }


condition:
	$a0
}