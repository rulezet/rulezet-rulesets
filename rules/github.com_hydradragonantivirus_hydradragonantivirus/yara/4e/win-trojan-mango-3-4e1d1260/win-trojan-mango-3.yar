rule Win_Trojan_Mango_3
{
strings:
	$a0 = { 86ce02b440b9d4018d960001cd21b8004233c933d2cd21b440b903008d96cd02cd21fe86c802b8 }


condition:
	$a0
}