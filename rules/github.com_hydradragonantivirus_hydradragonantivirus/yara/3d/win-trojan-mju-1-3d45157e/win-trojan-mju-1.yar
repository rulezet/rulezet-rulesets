rule Win_Trojan_MJU_1
{
strings:
	$a0 = { 02428bcacd2150b440b17acd21c744fe4de98f04b800428bcacd21b440b104cd21b43ecd21 }


condition:
	$a0
}