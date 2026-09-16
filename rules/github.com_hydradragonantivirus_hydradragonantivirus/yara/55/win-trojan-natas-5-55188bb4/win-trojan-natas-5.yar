rule Win_Trojan_Natas_5
{
strings:
	$a0 = { 8d36ed088d3e879931ed81f5861c45ffc581cf18b589f04e29be81e60bf687c379ec }


condition:
	$a0
}