rule Win_Trojan_Vlad_3
{
strings:
	$a0 = { e58b760083ee0333edc351b9e003d0c8f6d82e300446e2 }


condition:
	$a0
}