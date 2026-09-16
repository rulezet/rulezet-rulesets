rule Win_Trojan_Oulu_1
{
strings:
	$a0 = { 01e9e0fb8eeb33909001fb0f8bddbfa80390eb039012008b87ee03eb02901981c34400eb }


condition:
	$a0
}