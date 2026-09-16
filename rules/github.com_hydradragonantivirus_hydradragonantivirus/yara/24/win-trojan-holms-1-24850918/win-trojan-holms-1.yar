rule Win_Trojan_Holms_1
{
strings:
	$a0 = { d2720623d60bd02bef8bdeb62a381f0a7401b66f0a378a3cbacb58387f10b68db933528a098a4b100bf63a2a8bceb5 }


condition:
	$a0
}