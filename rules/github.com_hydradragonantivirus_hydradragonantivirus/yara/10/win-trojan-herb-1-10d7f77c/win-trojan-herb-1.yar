rule Win_Trojan_Herb_1
{
strings:
	$a0 = { 8d96a002b90500cd21b002b44233c999cd21b440b930018d960501cd21b42ccd2189963502b8 }


condition:
	$a0
}