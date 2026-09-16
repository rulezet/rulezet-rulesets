rule Win_Trojan_Dei_3
{
strings:
	$a0 = { fca11908e84200ba2108b91c00b440e809fc26c74515000026c745170000ba0508b440e8f5fb }


condition:
	$a0
}