rule Win_Trojan_Delf_68
{
strings:
	$a0 = { a9abc9207d2c89fa3a53584b66dd9357f2b1ac27ab9bd999e1ea1bd0a6c26941de790f493c5e2b2a80dd7c37402cae803f5ed13009a825b49526cdd0fab0aa }


condition:
	$a0
}