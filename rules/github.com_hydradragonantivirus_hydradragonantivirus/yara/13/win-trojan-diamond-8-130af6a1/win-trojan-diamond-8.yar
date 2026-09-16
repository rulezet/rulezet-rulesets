rule Win_Trojan_Diamond_8
{
strings:
	$a0 = { ffb926008b55022bd13bd0723a26294d038955 }


condition:
	$a0
}