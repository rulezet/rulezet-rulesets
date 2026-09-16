rule Win_Trojan_Grog_9
{
strings:
	$a0 = { cd2151522e8b0e0f0133d2b440cd215a59b80157cd21b43ecd210e1fb44feba10e1feb2090 }


condition:
	$a0
}