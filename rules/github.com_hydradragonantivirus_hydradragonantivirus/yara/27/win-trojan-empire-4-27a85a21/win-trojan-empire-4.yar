rule Win_Trojan_Empire_4
{
strings:
	$a0 = { 012ec6069c0200b82435cd212e891eb6022e8c06b802b425bafe01cd210e07ba5802e80f00e87000b82425bab602 }


condition:
	$a0
}