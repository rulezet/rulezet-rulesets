rule Win_Trojan_Small_4039
{
strings:
	$a0 = { bef167741281def14f3312568dbedc040000e8120000008da888385544192e8d }


condition:
	$a0
}