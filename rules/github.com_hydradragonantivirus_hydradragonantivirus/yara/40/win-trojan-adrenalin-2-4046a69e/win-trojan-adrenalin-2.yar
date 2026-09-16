rule Win_Trojan_Adrenalin_2
{
strings:
	$a0 = { fc8d963a02b41acd218e062c0033ff8bc8b050f2ae7559b84154af75f4b8483daf75ee32e4cd1a899638028db66502 }


condition:
	$a0
}