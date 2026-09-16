rule Win_Trojan_Trivial_296
{
strings:
	$a0 = { 4eb92700ba2c01cd217207e80600b44febf5cd20b8023dba9e00cd21b440b9 }


condition:
	$a0
}