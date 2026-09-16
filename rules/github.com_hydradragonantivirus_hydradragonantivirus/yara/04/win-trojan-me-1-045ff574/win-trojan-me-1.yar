rule Win_Trojan_Me_1
{
strings:
	$a0 = { 55e001000800ffff01030000460000000b0000000103 }


condition:
	$a0
}