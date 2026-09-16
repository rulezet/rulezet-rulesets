rule Win_Trojan_Vundo_43
{
strings:
	$a0 = { 807c24080160e811000000f8d13637a40dc2d310090e2f3cc51a4b2887db8d24 }


condition:
	$a0
}