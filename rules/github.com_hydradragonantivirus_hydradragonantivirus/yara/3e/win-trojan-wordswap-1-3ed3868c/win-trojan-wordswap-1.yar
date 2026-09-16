rule Win_Trojan_Wordswap_1
{
strings:
	$a0 = { 520369e7a3909fc8d86ca176e15a0369e7a2e16a606c6f9c47a45c782a8e97e15a0369e4f8696ce4f80069e7ae49736cdd679a9df4e15a7f6cd5686ce7926f94 }


condition:
	$a0
}