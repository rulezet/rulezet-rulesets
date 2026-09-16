rule Win_Trojan_DeadByte_8
{
strings:
	$a0 = { 6a000726a1f0043dad00742b909026c706f004ad00b82135cd21891e03018c060501b4498e062c00cd21b82125ba0a01cd21bafa01cd27c3 }


condition:
	$a0
}