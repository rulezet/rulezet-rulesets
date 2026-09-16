rule Win_Trojan_ExeHeader_12
{
strings:
	$a0 = { b8eefecd133dadde7452b81335cd212e891e????2e8c06????b40dcd21b436b200cd21 }


condition:
	$a0
}