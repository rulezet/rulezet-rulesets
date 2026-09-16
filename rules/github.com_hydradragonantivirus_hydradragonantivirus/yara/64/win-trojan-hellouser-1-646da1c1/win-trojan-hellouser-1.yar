rule Win_Trojan_Hellouser_1
{
strings:
	$a0 = { e800005d81ed08018db62401568b962201b95a018bfeac32c2aae2fac3 }


condition:
	$a0
}