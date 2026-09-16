rule Win_Trojan_AntiPC_1
{
strings:
	$a0 = { b37f8bf803f92e301d4181f9860776f296c179967f7f973e7ff4a5344cb6cf6c3c51 }


condition:
	$a0
}