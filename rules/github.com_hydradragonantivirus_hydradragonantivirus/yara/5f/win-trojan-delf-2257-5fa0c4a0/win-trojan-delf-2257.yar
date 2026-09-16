rule Win_Trojan_Delf_2257
{
strings:
	$a0 = { 2e746d70[0-12]537973496d672e736372 }

	$a1 = { 6f70656e[0-12]4e66782e736372 }

	$a2 = { 696d6731302e657865 }


condition:
	$a0 and $a1 and $a2
}