rule Win_Trojan_Ribbon_1
{
strings:
	$a0 = { 60009a0231c0a36200b80f27509a80057500a35e00b02650bf5c001e579a0b006e00833e5000 }


condition:
	$a0
}