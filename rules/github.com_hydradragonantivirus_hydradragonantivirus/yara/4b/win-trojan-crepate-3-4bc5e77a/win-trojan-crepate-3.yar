rule Win_Trojan_Crepate_3
{
strings:
	$a0 = { e80000eb1eb19fc4d29a8483e815b155a379bfb2c49aabceb1c428c0f3a69885b2bfa45e9ceb1ec49aabceb1c428c0f3 }


condition:
	$a0
}