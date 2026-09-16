rule Win_Trojan_Dei_2
{
strings:
	$a0 = { c3e846005b5f07b440b9460690ba9f07cd21c3268b450f80fc64c38d965a071e0e1fb43cb903 }


condition:
	$a0
}