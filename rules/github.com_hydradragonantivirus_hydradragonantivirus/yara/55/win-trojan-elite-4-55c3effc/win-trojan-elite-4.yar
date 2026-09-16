rule Win_Trojan_Elite_4
{
strings:
	$a0 = { bef8ffa5a5b9e1008b56008b5efab440cd2133c98bd18b5efab80042cd218b5e00c646fce9 }


condition:
	$a0
}