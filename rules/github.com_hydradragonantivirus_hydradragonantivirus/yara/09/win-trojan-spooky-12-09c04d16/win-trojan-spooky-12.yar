rule Win_Trojan_Spooky_12
{
strings:
	$a0 = { 0301b8cefa5058fa4c4cfb5b39c37405b8004ccd218c9eda020e0e1f078db6f6028dbe3702b90400f3a5b41a8d }


condition:
	$a0
}