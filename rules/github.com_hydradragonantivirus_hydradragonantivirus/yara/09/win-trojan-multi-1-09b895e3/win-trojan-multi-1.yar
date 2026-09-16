rule Win_Trojan_Multi_1
{
strings:
	$a0 = { 080033ffb800b18ec0268905263905740db800b98ec026 }


condition:
	$a0
}