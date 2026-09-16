rule Win_Trojan_Gotcha_6
{
strings:
	$a0 = { e800005e83ee1cbf0001fc2e807c180074108cd80510002e034416 }


condition:
	$a0
}