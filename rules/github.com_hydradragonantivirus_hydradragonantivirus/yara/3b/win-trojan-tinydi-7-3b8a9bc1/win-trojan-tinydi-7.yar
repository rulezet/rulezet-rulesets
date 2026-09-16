rule Win_Trojan_TinyDI_7
{
strings:
	$a0 = { cd218bd8061f8bd749b43fcd21055e005033c9b800 }


condition:
	$a0
}