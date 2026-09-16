rule Win_Trojan_MSShellcode_2
{
strings:
	$a0 = { fc31db648b43308b400c8b501c8b128b7220adad4e03063d32335f3275ef8b6a088b453c8b4c05788b4c0d1c01 }


condition:
	$a0
}