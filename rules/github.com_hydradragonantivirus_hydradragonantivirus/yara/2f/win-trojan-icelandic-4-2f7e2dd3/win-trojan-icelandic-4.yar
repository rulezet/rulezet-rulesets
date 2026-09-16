rule Win_Trojan_Icelandic_4
{
strings:
	$a0 = { 0686020a50535152561e8bda43803f2e740d803f0075 }


condition:
	$a0
}