rule Win_Trojan_Opax_2
{
strings:
	$a0 = { fc70327000647671236261636b75b51bfce60afa796c6f616429657482c6c6e2c13b081425024b340dc9 }


condition:
	$a0
}