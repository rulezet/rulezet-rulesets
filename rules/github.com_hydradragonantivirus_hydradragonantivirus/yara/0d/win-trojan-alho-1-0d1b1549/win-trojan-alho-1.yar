rule Win_Trojan_Alho_1
{
strings:
	$a0 = { 24268825f3a4061f33d2b80925cd21c3501e33c08ed8f6 }


condition:
	$a0
}