rule Win_Trojan_Word_3
{
strings:
	$a0 = { 24bfd12680351c4781ffa32c72 }


condition:
	$a0
}