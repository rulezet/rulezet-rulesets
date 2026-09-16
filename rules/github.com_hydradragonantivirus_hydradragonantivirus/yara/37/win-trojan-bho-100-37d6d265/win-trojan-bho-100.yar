rule Win_Trojan_BHO_100
{
strings:
	$a0 = { 6f70656e[0-4]5c636865662e696e69 }

	$a1 = { 5c57696e646f7773204e545c43757272656e7456657273696f6e }


condition:
	$a0 and $a1
}