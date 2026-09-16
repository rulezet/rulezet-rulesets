rule Win_Trojan_PS_44
{
strings:
	$a0 = { 02e887008d966c0459b440cd21b8024233c933d2cd21b440b97c028d960301cd218b96dc }


condition:
	$a0
}