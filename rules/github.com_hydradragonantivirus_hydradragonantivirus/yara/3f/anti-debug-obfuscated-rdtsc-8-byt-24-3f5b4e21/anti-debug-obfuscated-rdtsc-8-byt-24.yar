rule anti_debug__Obfuscated_RDTSC__8_byt_24_
{
strings:
	$a0 = { 5b8bcc83c1048bf483c610556a01536a026a03b82032977c }

condition:
	$a0
}