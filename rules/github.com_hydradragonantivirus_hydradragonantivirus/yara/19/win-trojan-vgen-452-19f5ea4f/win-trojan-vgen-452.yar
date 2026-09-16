rule Win_Trojan_VGEN_452
{
strings:
	$a0 = { 01b9580081340000817402000083c604e2f2c3b801faba4559cd10b419cd2150b410b202cd137303e9ed00b40eb2 }


condition:
	$a0
}