rule Win_Trojan_I13_26
{
strings:
	$a0 = { 330bba3e0bcd2126c74515000026c745170000b440 }


condition:
	$a0
}