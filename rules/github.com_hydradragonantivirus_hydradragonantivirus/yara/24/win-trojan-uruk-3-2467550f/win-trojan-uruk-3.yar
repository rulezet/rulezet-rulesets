rule Win_Trojan_Uruk_3
{
strings:
	$a0 = { 1e3d004b7503e85f001f595b5a58ebe7b003cf49 }


condition:
	$a0
}