rule Win_Trojan_Tiny_11
{
strings:
	$a0 = { 652a91b44ee800008bd6cd21ba9e00b82e5bae75fd66c705636f6d20cd2193b44080c127c3 }


condition:
	$a0
}