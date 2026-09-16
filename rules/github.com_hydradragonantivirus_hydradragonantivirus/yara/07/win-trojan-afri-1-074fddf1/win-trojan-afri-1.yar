rule Win_Trojan_Afri_1
{
strings:
	$a0 = { cd21b91efe72288bd1b8023dcd21 }


condition:
	$a0
}