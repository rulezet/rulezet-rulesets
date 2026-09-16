rule Win_Trojan_Como_1
{
strings:
	$a0 = { 8bdc8cca8ed2bc700781c4800050531e06e81f00e89c06e84c03e87800e8f504071f5b588ed08be32ea1f606502e }


condition:
	$a0
}