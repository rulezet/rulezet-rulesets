rule Win_Trojan_Mirror_2
{
strings:
	$a0 = { 5256571e063d004b7403e973012e833ea90301750a }


condition:
	$a0
}