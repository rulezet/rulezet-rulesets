rule Win_Trojan_Burger_22
{
strings:
	$a0 = { 90bc00fe505351525556571e06169c }


condition:
	$a0
}