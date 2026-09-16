rule Win_Trojan_Maverick_2
{
strings:
	$a0 = { 4026fe43fffaa1a94eba1294fa11c26aa1a3c83311c9442afe452efee4fd5f5f43eafa0d0bd1fc3e }


condition:
	$a0
}