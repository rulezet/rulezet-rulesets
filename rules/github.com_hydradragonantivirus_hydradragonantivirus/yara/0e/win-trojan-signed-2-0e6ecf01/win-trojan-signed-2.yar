rule Win_Trojan_Signed_2
{
strings:
	$a0 = { c08ed8803e31000074258a163100bb37008a0732c2 }


condition:
	$a0
}