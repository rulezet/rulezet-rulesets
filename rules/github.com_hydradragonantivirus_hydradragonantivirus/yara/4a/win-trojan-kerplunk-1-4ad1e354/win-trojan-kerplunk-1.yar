rule Win_Trojan_Kerplunk_1
{
strings:
	$a0 = { 0de8b6045a5981eae90c83d900e8c405b44033c9e8c105b468e8bc055a58b80042e8b405eb93 }


condition:
	$a0
}