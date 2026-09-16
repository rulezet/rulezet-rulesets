rule Win_Trojan_Verten_1
{
strings:
	$a0 = { cd213dadde7424b82135cd212e891e11012e8c061301b82125ba0301cd21b80009ba4d01cd }


condition:
	$a0
}