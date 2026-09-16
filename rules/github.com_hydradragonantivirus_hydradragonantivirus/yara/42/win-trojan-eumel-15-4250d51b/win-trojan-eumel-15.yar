rule Win_Trojan_Eumel_15
{
strings:
	$a0 = { 5d81ed0a018db62501568bfe8b967602b95101fcac32c2aae2fac3 }


condition:
	$a0
}