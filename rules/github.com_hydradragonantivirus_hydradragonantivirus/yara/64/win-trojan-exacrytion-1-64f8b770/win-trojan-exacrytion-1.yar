rule Win_Trojan_Exacrytion_1
{
strings:
	$a0 = { 8b4df48a91a0??42008855fe0fbe45fe898520ffffffdb8520ffffff83ec08d9e8dd1c2483ec08dd45d0dd1c24dd9d18ffffff????02000083c410dc0d????4100dcad18ffffff????????008845e78b0d??????01034df48a55e78811 }


condition:
	$a0
}