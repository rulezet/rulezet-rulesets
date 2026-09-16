rule Win_Trojan_Helloween_5
{
strings:
	$a0 = { 40eb02b43fe8160072022bc1c333c933d2b80242eb0890 }


condition:
	$a0
}