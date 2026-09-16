rule Win_Trojan_CMOS_1
{
strings:
	$a0 = { 13047e31ff8ed7bc007c8edf89e6b8809f8ec0b9be01f3a4ea5f00809fa14e0080fc9f74 }


condition:
	$a0
}