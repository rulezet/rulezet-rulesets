rule Win_Trojan_Gro_3
{
strings:
	$a0 = { bb8ec0bb00000e1fbab201b409cd21b28032f6b90100b8010acd13fec575f752b22eb402cd21 }


condition:
	$a0
}