rule Win_Trojan_Vienna4_1
{
strings:
	$a0 = { 0106b42fcd21891c8c4402b82435 }


condition:
	$a0
}