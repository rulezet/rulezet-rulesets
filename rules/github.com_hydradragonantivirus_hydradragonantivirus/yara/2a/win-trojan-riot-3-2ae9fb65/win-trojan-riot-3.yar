rule Win_Trojan_Riot_3
{
strings:
	$a0 = { 023dcd217303e97cff8bfa81c76200ab93b440b90400ba0001cd21b4408bf781c6fcff8104 }


condition:
	$a0
}