rule Win_Trojan_Dumador_56
{
strings:
	$a0 = { 0fcac7c32ce14d6ef28bd28bc0f6dcf7db86f40facd3220fbae3a389fa0fabc065d2d7d3da2ef7dfc0d4da0fafd88ac7c6c2b6c6c7e20fb3fb89d0f7d8 }


condition:
	$a0
}