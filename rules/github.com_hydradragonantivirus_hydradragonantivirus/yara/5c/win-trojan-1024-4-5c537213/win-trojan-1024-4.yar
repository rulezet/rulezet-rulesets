rule Win_Trojan_1024_4
{
strings:
	$a0 = { bf00b82125cd2133c08ec0b8f0f026 }


condition:
	$a0
}