rule Win_Trojan_Marina_3
{
strings:
	$a0 = { 3b01be6559b93e0031b4afa74646e2f8c3 }


condition:
	$a0
}