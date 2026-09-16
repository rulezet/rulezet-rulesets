rule Win_Trojan_MLTI_1
{
strings:
	$a0 = { 068600fb1fb8000150c33d03c6750a58 }


condition:
	$a0
}