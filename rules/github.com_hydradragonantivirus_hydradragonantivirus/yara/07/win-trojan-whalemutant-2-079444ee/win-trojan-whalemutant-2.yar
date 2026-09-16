rule Win_Trojan_WhaleMutant_2
{
strings:
	$a0 = { 1f81c361dce81e00ba02008137060403dae2f881c38d00 }


condition:
	$a0
}