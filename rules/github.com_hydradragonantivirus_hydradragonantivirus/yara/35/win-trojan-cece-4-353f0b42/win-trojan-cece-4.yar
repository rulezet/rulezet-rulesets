rule Win_Trojan_CeCe_4
{
strings:
	$a0 = { 213dcece7513bf04058bf7b99602f3a60bc9075e75 }


condition:
	$a0
}