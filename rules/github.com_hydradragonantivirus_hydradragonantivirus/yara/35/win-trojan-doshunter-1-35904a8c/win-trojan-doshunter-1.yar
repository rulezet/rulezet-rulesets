rule Win_Trojan_Doshunter_1
{
strings:
	$a0 = { 4b740e3d00c674052eff2edf02b8b707cf06531e52b9 }


condition:
	$a0
}