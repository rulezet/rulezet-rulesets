rule Win_Trojan_Blash_1
{
strings:
	$a0 = { 5b74565573696f6e5c52756e60f7ffef435b427e6c7e617e637e6b7e537e687e650d6c5d8d2a }


condition:
	$a0
}