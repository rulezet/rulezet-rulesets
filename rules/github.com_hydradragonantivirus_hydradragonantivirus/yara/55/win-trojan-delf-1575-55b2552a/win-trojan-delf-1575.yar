rule Win_Trojan_Delf_1575
{
strings:
	$a0 = { 81c4fcfeffff68005740008d44240450e8cbecffff68b83240008d44240450e8b4ecffff54e8c6ecffff54e8b8ecffff54e8b2ecffff54e8b4ecffff8bc4e835f0ffff81c404010000c3 }


condition:
	$a0
}