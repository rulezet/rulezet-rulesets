rule Win_Trojan_Emotet_2
{
strings:
	$a0 = { 558bec83ec1c56575333dbe86fe9ffffeb66689cf740008bfd033dfce04000893de4f64000ff35e4f640008b4ddc894dfcff75fc8b55e0891510d84000ff3510 }


condition:
	$a0
}