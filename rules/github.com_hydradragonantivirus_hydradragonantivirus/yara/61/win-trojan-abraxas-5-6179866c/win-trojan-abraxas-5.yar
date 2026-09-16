rule Win_Trojan_Abraxas_5
{
strings:
	$a0 = { b43c33c9ba9e00cd21b74093ba0001b99204cd21c3b4 }


condition:
	$a0
}