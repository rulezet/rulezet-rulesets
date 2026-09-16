rule Win_Trojan_SillyC_70
{
strings:
	$a0 = { 81ed0301ffb6a401ffb6a201b44e8d96a601b90000cd217207e81100b44febee58a3000158a20201b8000150c3a19c }


condition:
	$a0
}