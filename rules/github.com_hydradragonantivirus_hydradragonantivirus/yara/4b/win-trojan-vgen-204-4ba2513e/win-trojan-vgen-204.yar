rule Win_Trojan_VGEN_204
{
strings:
	$a0 = { 0400f7d9f7d9cc80c5008d86c905fec080f300fec8ffd0072334eb001f807144320005f27144eb003d80716c65302e }


condition:
	$a0
}