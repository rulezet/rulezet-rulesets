rule Win_Trojan_England_2
{
strings:
	$a0 = { a5a433f68edec45c4c896c048c4c06ba }


condition:
	$a0
}