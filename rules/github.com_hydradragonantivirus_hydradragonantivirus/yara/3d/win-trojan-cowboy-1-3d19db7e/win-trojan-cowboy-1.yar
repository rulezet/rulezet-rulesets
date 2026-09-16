rule Win_Trojan_Cowboy_1
{
strings:
	$a0 = { 2709b97101000743040de2f958595b9dc3fab002ba0000b9bc0233dbcd269dfbc3b430cd213c }


condition:
	$a0
}