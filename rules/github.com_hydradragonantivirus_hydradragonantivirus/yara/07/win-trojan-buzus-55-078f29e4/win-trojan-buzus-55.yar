rule Win_Trojan_Buzus_55
{
strings:
	$a0 = { 9c81442404a270a072ff342483c404e81f090000609ce8000000008b1c2483c3 }


condition:
	$a0
}