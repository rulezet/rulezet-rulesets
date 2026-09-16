rule Win_Trojan_Delf_2167
{
strings:
	$a0 = { 52305bc300ffffffff4000000050686f656e6978205241542076312e30300d0a0d0a }


condition:
	$a0
}