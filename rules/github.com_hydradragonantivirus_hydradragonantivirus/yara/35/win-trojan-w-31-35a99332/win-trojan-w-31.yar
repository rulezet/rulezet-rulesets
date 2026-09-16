rule Win_Trojan_W_31
{
strings:
	$a0 = { a702836c3c08b440baa702b93e00cd21b8004233c9ba0004cd21b43fbaa702b90002cd218b441c }


condition:
	$a0
}