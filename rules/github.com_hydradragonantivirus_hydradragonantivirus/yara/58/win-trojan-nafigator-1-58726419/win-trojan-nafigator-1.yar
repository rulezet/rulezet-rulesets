rule Win_Trojan_Nafigator_1
{
strings:
	$a0 = { b440b9de038bd5cd21722cb8004233c933d2cd21b440b918008d96db0381bedb034d5a7407b9 }


condition:
	$a0
}