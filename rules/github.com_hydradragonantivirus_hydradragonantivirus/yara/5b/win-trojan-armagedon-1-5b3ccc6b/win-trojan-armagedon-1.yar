rule Win_Trojan_Armagedon_1
{
strings:
	$a0 = { 8becc7460200015dc341726d616765646f6e2032eb3c90532a }


condition:
	$a0
}