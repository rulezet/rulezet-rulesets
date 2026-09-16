rule Win_Trojan_Vlab_1
{
strings:
	$a0 = { 080183fd00740dbe260701eebf0001b90300f3a4c6861d0700b41abaf20601eacd21b44eba1e0701eacd217227 }


condition:
	$a0
}