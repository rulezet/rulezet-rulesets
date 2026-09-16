rule Win_Trojan_Philis_121
{
strings:
	$a0 = { 0f00c25aba0000000064ff3257d3cf5f64892276037701 }


condition:
	$a0
}