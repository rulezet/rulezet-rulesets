rule Win_Trojan_Daddy_2
{
strings:
	$a0 = { e58b760083ee0333edc351b9f803d0c8f6d82e300446e2f659c3 }


condition:
	$a0
}