rule Win_Trojan_Ilse_1
{
strings:
	$a0 = { 9a0000bb005589e5b800019a3005bb0081ec0001e8dbffe8c7ffe896ffe87bff68c01d9a8a02bb00a306028916080268 }


condition:
	$a0
}