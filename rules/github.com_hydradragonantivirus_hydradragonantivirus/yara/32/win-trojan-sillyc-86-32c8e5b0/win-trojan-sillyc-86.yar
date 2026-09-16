rule Win_Trojan_SillyC_86
{
strings:
	$a0 = { 03008986a901b440b9c3008d960301cd21b8004233c933d2cd21b440b903008d96a801cd21b43e }


condition:
	$a0
}