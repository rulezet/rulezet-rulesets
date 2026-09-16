rule Win_Trojan_Boot_12
{
strings:
	$a0 = { 5eebeeebfe9000f8f8f5f5dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfacabbeadabdfdfaca6acabba }


condition:
	$a0
}