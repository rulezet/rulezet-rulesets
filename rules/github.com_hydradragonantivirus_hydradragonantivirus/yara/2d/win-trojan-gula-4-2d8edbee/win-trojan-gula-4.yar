rule Win_Trojan_Gula_4
{
strings:
	$a0 = { edb4e5d47735da76c0a7f13122b822c1bc10fd0ea32fa81cef7ac472d91fbc10adefefa32f7aec72 }


condition:
	$a0
}