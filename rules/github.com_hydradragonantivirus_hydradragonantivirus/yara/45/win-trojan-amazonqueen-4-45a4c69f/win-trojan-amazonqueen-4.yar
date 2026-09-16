rule Win_Trojan_AmazonQueen_4
{
strings:
	$a0 = { 1fe800005d81ed050006b4accd213c3075132e3b9eda017d39b4aecd21b4098d967f00cd2133c08ec0 }


condition:
	$a0
}