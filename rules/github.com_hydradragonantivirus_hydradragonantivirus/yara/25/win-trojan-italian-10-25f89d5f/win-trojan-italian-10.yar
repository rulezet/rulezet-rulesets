rule Win_Trojan_Italian_10
{
strings:
	$a0 = { 06d3e02dc0078ec0be007c8bfeb900 }


condition:
	$a0
}