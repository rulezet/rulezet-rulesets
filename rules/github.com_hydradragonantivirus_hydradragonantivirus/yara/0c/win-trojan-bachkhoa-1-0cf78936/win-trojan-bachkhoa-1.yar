rule Win_Trojan_BachKhoa_1
{
strings:
	$a0 = { 03d1e983e9102e310783c302e2f8c32ea3d80e2e891e }


condition:
	$a0
}