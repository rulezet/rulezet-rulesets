rule Win_Trojan_LdPinch_63
{
strings:
	$a0 = { 7a6a707ea26c666f6c687262706f6c82a4c3eeeeedf5a2cdece1e782406f6a6e626f6a67b8a26f67686c706c727967a2686c6e6d6c6f676f7079a26a656e676f6a69 }


condition:
	$a0
}