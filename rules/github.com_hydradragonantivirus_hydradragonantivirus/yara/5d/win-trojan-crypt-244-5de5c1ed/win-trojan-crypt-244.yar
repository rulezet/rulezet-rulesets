rule Win_Trojan_Crypt_244
{
strings:
	$a0 = { 68f5bf4500e90600017159368f01e906 }

	$a1 = { 8c665a6658665966f7f966506652e9 }


condition:
	$a0 and $a1
}