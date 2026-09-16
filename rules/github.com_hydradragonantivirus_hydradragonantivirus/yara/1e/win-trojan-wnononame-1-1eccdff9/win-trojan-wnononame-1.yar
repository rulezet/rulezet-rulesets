rule Win_Trojan_WnoNoName_1
{
strings:
	$a0 = { 5f82ef06028cff84e8f18cc8b205d4e98dca04c251b9270251baf005fdf4a5cdcc0f20bf410334002f813f410301cd75 }


condition:
	$a0
}