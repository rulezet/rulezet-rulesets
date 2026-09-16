rule Win_Trojan_Karud_2
{
strings:
	$a0 = { 8b45ecba24ea1813e8615ffbff }


condition:
	$a0
}