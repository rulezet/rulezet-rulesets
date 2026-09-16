rule Win_Trojan_Picket_2
{
strings:
	$a0 = { 8b6efe83c50336c744140001b91f038db62c018bfead35 }


condition:
	$a0
}