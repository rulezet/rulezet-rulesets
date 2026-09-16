rule Win_Trojan_Insert_2
{
strings:
	$a0 = { 0e0e1f07e4400ac074faa2fd00fcb902018bf95157f3a4bf0801e83900b4405a599c2eff1e7100 }


condition:
	$a0
}