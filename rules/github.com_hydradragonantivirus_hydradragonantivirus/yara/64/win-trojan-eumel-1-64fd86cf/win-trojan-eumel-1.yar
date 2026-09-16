rule Win_Trojan_Eumel_1
{
strings:
	$a0 = { 5d81ed0a018db62501568bfe8b968d02b96801fcac32c2aae2fac3 }


condition:
	$a0
}