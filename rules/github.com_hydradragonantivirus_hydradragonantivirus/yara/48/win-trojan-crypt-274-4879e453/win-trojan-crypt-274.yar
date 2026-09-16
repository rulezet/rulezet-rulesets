rule Win_Trojan_Crypt_274
{
strings:
	$a0 = { e7e8c4fdffffffd6e9f8fdffff81c7886541be418ae4f7d7adfc3b4a1889e48d3c189b0f84b6ff }


condition:
	$a0
}