rule Win_Trojan_HaryAnto_2
{
strings:
	$a0 = { fe33c9e2feb401b90008cd10e2fe33 }


condition:
	$a0
}