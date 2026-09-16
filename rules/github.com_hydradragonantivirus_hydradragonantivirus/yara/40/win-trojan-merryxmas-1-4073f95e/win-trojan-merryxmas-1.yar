rule Win_Trojan_MerryXmas_1
{
strings:
	$a0 = { 35cd2126813f65137503e93301b82135cd212e8c06e4 }


condition:
	$a0
}