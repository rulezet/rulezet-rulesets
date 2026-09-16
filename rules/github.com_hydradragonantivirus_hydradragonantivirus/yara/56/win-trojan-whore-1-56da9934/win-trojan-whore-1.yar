rule Win_Trojan_Whore_1
{
strings:
	$a0 = { 496e204d656d6f7279204f66205468652057686f726521ff00020408002b }


condition:
	$a0
}