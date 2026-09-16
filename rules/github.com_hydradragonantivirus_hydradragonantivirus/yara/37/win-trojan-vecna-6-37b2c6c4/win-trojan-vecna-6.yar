rule Win_Trojan_Vecna_6
{
strings:
	$a0 = { 01025080fa807e1b268b4f11c1e904260fb6471026f7671603c841262b4f18b601eb0ab408cd13 }


condition:
	$a0
}