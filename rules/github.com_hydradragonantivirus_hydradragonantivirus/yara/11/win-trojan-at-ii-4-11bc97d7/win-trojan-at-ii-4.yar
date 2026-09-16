rule Win_Trojan_AT_II_4
{
strings:
	$a0 = { 0e560eb02e508ec033ffb178f3a46a12cb56be84008ed9 }


condition:
	$a0
}