rule Win_Trojan_ZhengZhou_1
{
strings:
	$a0 = { 0400a31304b106d3e0508ec0be007cbf000bb90002fcf3a4b83f0b50cb8cc88ed88ec033c0cd13 }


condition:
	$a0
}