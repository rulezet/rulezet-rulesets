rule Win_Trojan_Vienna_104
{
strings:
	$a0 = { c2c900cd21eb64b43fb90300ba0a }


condition:
	$a0
}