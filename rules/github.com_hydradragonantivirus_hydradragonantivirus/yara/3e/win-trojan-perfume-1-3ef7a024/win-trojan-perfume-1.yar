rule Win_Trojan_Perfume_1
{
strings:
	$a0 = { fcbf0000f3a481ec000406bfbc0057cb }


condition:
	$a0
}