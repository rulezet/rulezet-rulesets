rule Win_Trojan_Peed_416
{
strings:
	$a0 = { 9090909090b8??f04000bb??f14000fe00403bc375f98f8f8f8f8fb7????3fff8a6f0b80c5ffff3fffbe??f13fffe759ffffff8a0d8afdbd??f13ffff2a382bf273c????3fff71d767??f13fff693f67ff0fffff67ffff3fffb7????3ffffe0fb7????3f }


condition:
	$a0
}