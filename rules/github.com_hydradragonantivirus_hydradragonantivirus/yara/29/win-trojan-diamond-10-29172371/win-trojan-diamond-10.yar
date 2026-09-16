rule Win_Trojan_Diamond_10
{
strings:
	$a0 = { ffb92a008b55022bd13bd0723c909026294d038955 }


condition:
	$a0
}