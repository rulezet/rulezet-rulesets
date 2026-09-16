rule Win_Trojan_OneHalf_18
{
strings:
	$a0 = { 8ed0bc007c8bf45007501ffb8bd8832e130405b106cd12d3e0ba80008ec0b90a00b8080206cd13b8ed00 }


condition:
	$a0
}