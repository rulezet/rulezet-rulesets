rule Win_Trojan_Virut_203
{
strings:
	$a0 = { e8??000000[0-50]558b6c240403c1816c2404??????002d0001000073b981ed0510??008d85??10??008a90a6ffffffe8a7ffffff }


condition:
	$a0
}