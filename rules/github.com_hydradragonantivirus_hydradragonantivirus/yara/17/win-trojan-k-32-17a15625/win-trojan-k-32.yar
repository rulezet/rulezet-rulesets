rule Win_Trojan_K_32
{
strings:
	$a0 = { 4b6f7504b86b4fcf80fc4b75ea }


condition:
	$a0
}