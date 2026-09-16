rule Win_Spyware_8909_1
{
strings:
	$a0 = { 565683c404893c244048f7d0eb008b3c2483c404e8c6010000 }


condition:
	$a0
}