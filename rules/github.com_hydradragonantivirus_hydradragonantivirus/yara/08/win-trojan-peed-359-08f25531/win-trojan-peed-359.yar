rule Win_Trojan_Peed_359
{
strings:
	$a0 = { 81ef97f7ffff81ff69080000742d81ffddfa00007f25cd40 }


condition:
	$a0
}