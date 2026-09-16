rule Win_Trojan_Hupigon_1550
{
strings:
	$a0 = { de6196bf6366cbcf3e87a668eef6720731fc0ebd86859c67f6e039725007940cd6f2ffa32afb0d696c151a76836af8e0dfa4cdc320f4b7b7763f3d75f69a61f847b291d32f1aaadf10c3e44f1f83 }


condition:
	$a0
}