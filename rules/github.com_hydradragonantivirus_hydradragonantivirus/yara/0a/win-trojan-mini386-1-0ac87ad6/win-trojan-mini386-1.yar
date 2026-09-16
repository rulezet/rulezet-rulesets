rule Win_Trojan_Mini386_1
{
strings:
	$a0 = { 030097b4408bd5b9720090cd21b800425a59cd21fdc604e9897c01fc87d6b90400b440cd21b44f }


condition:
	$a0
}