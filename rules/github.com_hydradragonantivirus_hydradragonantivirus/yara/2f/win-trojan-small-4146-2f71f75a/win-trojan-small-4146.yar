rule Win_Trojan_Small_4146
{
strings:
	$a0 = { e815000000be8000??98c1c60fe81f00000039 }


condition:
	$a0
}