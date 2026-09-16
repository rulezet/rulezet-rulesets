rule Win_Trojan_Companion_29
{
strings:
	$a0 = { 8bde8c4f04061e071fcd21c38bd7b82e5bae75fd66c705636f6d00cd2172c893b440b161eb }


condition:
	$a0
}