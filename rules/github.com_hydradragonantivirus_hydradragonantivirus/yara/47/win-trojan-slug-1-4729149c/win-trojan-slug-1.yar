rule Win_Trojan_Slug_1
{
strings:
	$a0 = { b97003b440cc33c981efff008bd7b80042ccba7a03b90200b440cce85100b43eccba8303e8 }


condition:
	$a0
}