rule Win_Trojan_Newgen_1
{
strings:
	$a0 = { c7f5fdb95403908bf281c6490133db8a3c8a0532c78805 }


condition:
	$a0
}