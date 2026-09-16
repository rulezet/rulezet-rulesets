rule Win_Trojan_Bios_2
{
strings:
	$a0 = { 01e8090007e80e00ea0000ffffa5a58944fc8c44fec30e1fe800005b89de83c31e8b07cd215e }


condition:
	$a0
}