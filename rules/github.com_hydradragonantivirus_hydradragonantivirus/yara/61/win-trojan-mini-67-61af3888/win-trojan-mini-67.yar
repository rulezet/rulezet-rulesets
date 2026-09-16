rule Win_Trojan_Mini_67
{
strings:
	$a0 = { 9e00cd2193b43f89f25459cd21803cfe7413055300502bc9f7e1b442cd2159b4405a52cd21b44f }


condition:
	$a0
}