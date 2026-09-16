rule Win_Trojan_Screamer_1
{
strings:
	$a0 = { c51e84002e899ed3002e8c9ed5008cc34b8edb812e }


condition:
	$a0
}