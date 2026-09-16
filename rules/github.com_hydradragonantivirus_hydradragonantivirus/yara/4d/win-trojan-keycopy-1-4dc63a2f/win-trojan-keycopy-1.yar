rule Win_Trojan_KeyCopy_1
{
strings:
	$a0 = { e914056b4579436f50593d433a5c4b4559434f5059 }


condition:
	$a0
}