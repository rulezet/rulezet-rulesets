rule Win_Trojan_Vienna_49
{
strings:
	$a0 = { bf0001fca5a5a58bf252b42ccd215a80 }


condition:
	$a0
}