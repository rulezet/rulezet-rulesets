rule Win_Trojan_Dikshev_12
{
strings:
	$a0 = { 2abf9e0091b44e8bd6cd218bd7b82e5bae75fd66c705434f4d20cd21720793b129b440ebe2 }


condition:
	$a0
}