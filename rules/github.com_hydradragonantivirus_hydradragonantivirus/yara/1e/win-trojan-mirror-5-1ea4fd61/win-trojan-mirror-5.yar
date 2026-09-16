rule Win_Trojan_Mirror_5
{
strings:
	$a0 = { b80042e84600b440b99c0333d2e83c00 }


condition:
	$a0
}