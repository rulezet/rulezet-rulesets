rule Win_Trojan_PS_5
{
strings:
	$a0 = { e90000e800005d81ed06011e06b82435cd2106538d96????b82425cd210e070e1f0e07b41a8d96????cd21b200b447 }


condition:
	$a0
}