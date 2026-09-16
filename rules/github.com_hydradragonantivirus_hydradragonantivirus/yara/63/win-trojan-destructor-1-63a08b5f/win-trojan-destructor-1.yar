rule Win_Trojan_Destructor_1
{
strings:
	$a0 = { 7dfc1e0e8e5e13c43e84001f89bea3008c86a50089 }


condition:
	$a0
}