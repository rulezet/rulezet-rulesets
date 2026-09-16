rule Win_Trojan_H8_2
{
strings:
	$a0 = { ffcd21c7060601eb010bc07507eb0180b4fecd21e84003 }


condition:
	$a0
}