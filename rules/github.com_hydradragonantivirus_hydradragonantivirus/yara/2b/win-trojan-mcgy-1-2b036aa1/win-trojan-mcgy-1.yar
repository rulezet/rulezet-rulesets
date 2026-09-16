rule Win_Trojan_Mcgy_1
{
strings:
	$a0 = { 0b00fcf3a4061fc645fe0fcd1233db2dc000b106d3e08ec0065333c033d2cd13b80902b5 }


condition:
	$a0
}