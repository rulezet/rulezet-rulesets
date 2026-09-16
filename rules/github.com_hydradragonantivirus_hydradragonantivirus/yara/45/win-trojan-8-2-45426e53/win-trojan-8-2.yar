rule Win_Trojan_8_2
{
strings:
	$a0 = { 0fe0cd213d314c753d2e813e2b004d5a }


condition:
	$a0
}