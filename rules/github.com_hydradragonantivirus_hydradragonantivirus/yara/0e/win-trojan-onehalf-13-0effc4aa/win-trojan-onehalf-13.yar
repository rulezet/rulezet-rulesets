rule Win_Trojan_OneHalf_13
{
strings:
	$a0 = { a556d83c036faa62a5330723817800db141fc86a55271cf1536a7bff60704060a88176e5d1533d7ebbbe23a8803509bb }


condition:
	$a0
}