rule Win_Trojan_Crypt_215
{
strings:
	$a0 = { 688f26e5f58134249fbcf36f893c24e9f4feffff8bff83c4048b04248bff83c404e88cf7ffff8b }


condition:
	$a0
}