rule Win_Trojan_Vienna_93
{
strings:
	$a0 = { 51b94c04ba4111bf40118a058bdf4b8a272ae08827e2f7fc }


condition:
	$a0
}