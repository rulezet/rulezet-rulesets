rule Win_Trojan_DIE_1
{
strings:
	$a0 = { b440cdd472122689551526895517b91800b440ba2b03cdd4e9a0fe53b82012cd2f268a1db8 }


condition:
	$a0
}