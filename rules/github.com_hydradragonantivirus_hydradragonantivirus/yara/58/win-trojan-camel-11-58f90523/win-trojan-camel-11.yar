rule Win_Trojan_Camel_11
{
strings:
	$a0 = { e800005d83ed??8d86????ffd0 }

	$a1 = { 8d76??89f7b9e100ad7304abe2fac3 }


condition:
	$a0 and $a1
}