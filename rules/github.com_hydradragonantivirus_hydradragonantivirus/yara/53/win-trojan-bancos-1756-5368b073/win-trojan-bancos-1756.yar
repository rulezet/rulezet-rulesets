rule Win_Trojan_Bancos_1756
{
strings:
	$a0 = { df5f76b2bdb89aa1ecfeec158a39e3a82257207ae1ccd811dcd03800fa380fddc7b2f7e4980ddd98973e6899694466302f83e15ea3801a81c350181e0715db0e4046c9a3a353 }


condition:
	$a0
}