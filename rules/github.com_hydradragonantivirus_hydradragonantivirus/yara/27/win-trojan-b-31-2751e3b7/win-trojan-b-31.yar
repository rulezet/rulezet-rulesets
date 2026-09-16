rule Win_Trojan_B_31
{
strings:
	$a0 = { 13cd2f0e1f891e40018c0642010e07b801028bd8b90100ba8000e82f008bfb }


condition:
	$a0
}