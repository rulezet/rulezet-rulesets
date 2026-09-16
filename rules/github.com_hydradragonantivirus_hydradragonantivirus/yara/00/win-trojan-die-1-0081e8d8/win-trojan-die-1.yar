rule Win_Trojan_Die_1
{
strings:
	$a0 = { fa772526896d1583ed03892e9f02b440b92303cdd4720e26895515b440b90500ba9e02cdd4 }


condition:
	$a0
}