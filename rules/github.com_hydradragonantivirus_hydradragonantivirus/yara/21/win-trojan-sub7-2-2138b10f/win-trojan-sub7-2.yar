rule Win_Trojan_Sub7_2
{
strings:
	$a0 = { ab66a801186874716140fc74703a2f2f00af2d153572444315ededbf6b9a634d6f7a696c6c612f349e34205b12fd5f }


condition:
	$a0
}