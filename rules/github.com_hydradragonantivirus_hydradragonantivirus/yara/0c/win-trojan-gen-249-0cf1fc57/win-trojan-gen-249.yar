rule Win_Trojan_Gen_249
{
strings:
	$a0 = { c6036dcafde9fd049e7d3efd3ca90c963c4c01eb04768052a16a3ca366010422116e0c6a065400 }


condition:
	$a0
}