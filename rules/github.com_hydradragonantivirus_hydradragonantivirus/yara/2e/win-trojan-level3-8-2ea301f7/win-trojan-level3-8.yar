rule Win_Trojan_Level3_8
{
strings:
	$a0 = { ff32dbcd13b4fecd13b802faba4559 }


condition:
	$a0
}