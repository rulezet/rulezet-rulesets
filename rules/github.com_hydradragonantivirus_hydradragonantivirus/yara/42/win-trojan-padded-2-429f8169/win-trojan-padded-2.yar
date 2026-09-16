rule Win_Trojan_Padded_2
{
strings:
	$a0 = { 3d8bd6cd218bd8be7704e8ef00b43f }


condition:
	$a0
}