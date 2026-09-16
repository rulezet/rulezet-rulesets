rule Win_Trojan_Constructor_3
{
strings:
	$a0 = { 01001aeb4ec3006e6bef5913b407012500b61868040200de082308de08281800009a18c118bd5a47dce7d500bce93d }


condition:
	$a0
}