rule Win_Trojan_Annyit_1
{
strings:
	$a0 = { 02a305001e8b16820283e20fb990028cd8488ed8b440e8ae001f725733d2a1840248b92000f7 }


condition:
	$a0
}