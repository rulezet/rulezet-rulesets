rule Win_Trojan_Psr_1
{
strings:
	$a0 = { 72808d8c02e1c4e705caa558077206883503cbebb28abc5b077302cacbeb74e6beca44f9cff9d407 }


condition:
	$a0
}