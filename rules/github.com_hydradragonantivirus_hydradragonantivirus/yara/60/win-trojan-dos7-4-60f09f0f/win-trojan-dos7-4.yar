rule Win_Trojan_Dos7_4
{
strings:
	$a0 = { ebfc2d02e7b701ba0000cd13ebec06510726c70600004c4d26c7060200415307c706070168 }


condition:
	$a0
}