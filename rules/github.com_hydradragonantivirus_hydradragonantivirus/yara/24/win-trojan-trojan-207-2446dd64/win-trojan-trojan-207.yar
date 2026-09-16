rule Win_Trojan_Trojan_207
{
strings:
	$a0 = { a4c6866f06ffb41a8d964406cd21b82435cd21899e4006 }


condition:
	$a0
}