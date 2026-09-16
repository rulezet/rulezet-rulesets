rule Win_Trojan_Mandra_6
{
strings:
	$a0 = { b90300ba5e00fec45050cd2158b9950233d2cd21b800 }


condition:
	$a0
}