rule Win_Trojan_Manzon_7
{
strings:
	$a0 = { be000156b9a106c70418ddc64402828134a0664646e2f8 }


condition:
	$a0
}