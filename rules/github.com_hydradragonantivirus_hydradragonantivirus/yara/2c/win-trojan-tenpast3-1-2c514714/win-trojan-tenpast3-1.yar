rule Win_Trojan_TenPast3_1
{
strings:
	$a0 = { 01ffe0b800f08ed8baf0ffb80125cd21b80325cd21c3 }


condition:
	$a0
}