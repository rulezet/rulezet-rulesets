rule Win_Trojan_Nomad_3
{
strings:
	$a0 = { 429933c9cd21b440b91c008d96d202cd21b801572e8b8ebd022e8b96bf0280e1e080c91090 }


condition:
	$a0
}