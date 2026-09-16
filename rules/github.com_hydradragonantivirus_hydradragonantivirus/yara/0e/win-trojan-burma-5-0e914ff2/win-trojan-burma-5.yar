rule Win_Trojan_Burma_5
{
strings:
	$a0 = { e80601e82901e82100e8de00e82b01e8f700e8cd00e8d200e8ee00e81101e8c900e81601e8e200e9fe00505351 }


condition:
	$a0
}