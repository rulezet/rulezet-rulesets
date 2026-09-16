rule Win_Trojan_FSMM_1
{
strings:
	$a0 = { 117da728c20ddbad2203f40b3ed9a48426adec4e2d5bcbb63b09b0e82afaa3875e9fe2d459ac19f1 }


condition:
	$a0
}