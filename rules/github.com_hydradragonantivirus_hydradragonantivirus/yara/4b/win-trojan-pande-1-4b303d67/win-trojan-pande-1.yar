rule Win_Trojan_Pande_1
{
strings:
	$a0 = { 060000cd20e8ad05558b6e14e839008bdd5d8b46020510002e0147262e01471ce8a205bcf0ff8ed4bcfeffea0000f0 }


condition:
	$a0
}