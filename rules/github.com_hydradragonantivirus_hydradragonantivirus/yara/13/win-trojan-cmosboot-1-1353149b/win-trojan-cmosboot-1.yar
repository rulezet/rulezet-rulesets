rule Win_Trojan_Cmosboot_1
{
strings:
	$a0 = { e800005b2e80bff900ff7503e9f00131c08ed0bc007c8ed83ea1130448483ea31304b106d3e02dc0078ec0be007c89 }


condition:
	$a0
}