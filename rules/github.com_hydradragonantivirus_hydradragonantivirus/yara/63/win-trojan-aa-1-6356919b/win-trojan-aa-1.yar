rule Win_Trojan_AA_1
{
strings:
	$a0 = { 813e00000eb8742231c98ed9b80042cd78baec01b9fa01b440cd788b0e7f02b800908ed831d2b440 }


condition:
	$a0
}