rule Win_Trojan_BitAddict_4
{
strings:
	$a0 = { e2bf8ec089de33ffb9dd01f3a489de33ffb9dd01f3a674 }


condition:
	$a0
}