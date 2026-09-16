rule Win_Trojan_Denzuk_1
{
strings:
	$a0 = { b40ecd2183c702b41aba5c05cd211e061f8bd7b90700b44ecd211fb40e2e8a168705cd21b8 }


condition:
	$a0
}