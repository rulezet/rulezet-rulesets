rule Win_Trojan_Milan_5
{
strings:
	$a0 = { 213c037516b42ccd2188360f01b405b600b200b1018a2e0f01cd13b44ccd21ba9e00b80043 }


condition:
	$a0
}