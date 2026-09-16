rule Win_Trojan_Lame_7
{
strings:
	$a0 = { 01e800005d81ed08018db61e0189f7b9cd00ad3400d0c8aae2f8c686b802008dbee5028db6b202b90500f3a4 }


condition:
	$a0
}