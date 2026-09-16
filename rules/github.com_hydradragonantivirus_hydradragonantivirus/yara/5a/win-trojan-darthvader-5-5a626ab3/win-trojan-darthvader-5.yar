rule Win_Trojan_DarthVader_5
{
strings:
	$a0 = { e800005e83ee038936f000a3fe0031c08ed88e06ae00b800908ed831ff4781ff000f77585731f6b95801f3a65fe302ebec2e8b36f0002e893ef2000e1fb95801 }


condition:
	$a0
}