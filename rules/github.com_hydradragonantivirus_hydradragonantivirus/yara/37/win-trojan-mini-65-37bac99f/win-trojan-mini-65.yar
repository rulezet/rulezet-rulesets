rule Win_Trojan_Mini_65
{
strings:
	$a0 = { 9e00cd2193b43f89f289e1cd21803c807413055100502bc9f7e1b442cd2159b4405a52cd21b44f }


condition:
	$a0
}