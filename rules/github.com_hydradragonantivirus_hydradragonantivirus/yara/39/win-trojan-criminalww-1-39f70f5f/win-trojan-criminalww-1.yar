rule Win_Trojan_CriminalWW_1
{
strings:
	$a0 = { 5e83ee03b87042cd213d77777502eb62e80705290602008b2e02008cda2bea06b44abbffffcd21b44acd214a8edaa103008bd8e8e4042bd88bc303d0a3030042 }


condition:
	$a0
}