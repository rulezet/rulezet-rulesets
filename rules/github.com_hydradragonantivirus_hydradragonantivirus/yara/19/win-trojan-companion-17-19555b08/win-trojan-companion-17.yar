rule Win_Trojan_Companion_17
{
strings:
	$a0 = { 2e652a91b44e565acd21ba9e00b82e5bae75fd66c705636f6d00cd2193b440b128ba0001cd21c3 }


condition:
	$a0
}