rule Win_Trojan_Small_3958
{
strings:
	$a0 = { 53535353bfb8274100ff1785c0752d }


condition:
	$a0
}