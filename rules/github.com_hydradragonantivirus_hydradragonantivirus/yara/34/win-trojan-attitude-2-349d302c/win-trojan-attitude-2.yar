rule Win_Trojan_Attitude_2
{
strings:
	$a0 = { b801faba4559cd16e800005d81ed0d018bc5051a0150 }


condition:
	$a0
}