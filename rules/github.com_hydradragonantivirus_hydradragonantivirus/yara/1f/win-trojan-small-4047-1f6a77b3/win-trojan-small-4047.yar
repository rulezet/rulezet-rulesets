rule Win_Trojan_Small_4047
{
strings:
	$a0 = { bef1a7731281def14f3312568dbedc040000e8120000008da888385544192e8d }


condition:
	$a0
}