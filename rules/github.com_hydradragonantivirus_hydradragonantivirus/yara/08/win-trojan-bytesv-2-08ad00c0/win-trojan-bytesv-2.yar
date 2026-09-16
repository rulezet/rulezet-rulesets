rule Win_Trojan_ByteSV_2
{
strings:
	$a0 = { 1e06e800005d81edca028d4603500e1fb9bf02908db603008aa6c202302446e2fbc3 }


condition:
	$a0
}