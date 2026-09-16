rule Win_Trojan_Thor9_1
{
strings:
	$a0 = { 0134004d9526cf82d8b65034d1e82c03e82ca409fce8cde8a6100226ac2a77a7e8313306c0 }


condition:
	$a0
}