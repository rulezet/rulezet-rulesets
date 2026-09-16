rule Win_Trojan_Small_4147
{
strings:
	$a0 = { e815000000be800032f8c1c60fe81f00000039ef75ef891c24c38d1d22 }


condition:
	$a0
}