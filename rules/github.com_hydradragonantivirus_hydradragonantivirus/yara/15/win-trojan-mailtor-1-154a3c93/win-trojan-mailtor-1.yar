rule Win_Trojan_Mailtor_1
{
strings:
	$a0 = { 0200b400cd13b80602cd13730e80269004df4f75edcd1855320206060653cf }


condition:
	$a0
}