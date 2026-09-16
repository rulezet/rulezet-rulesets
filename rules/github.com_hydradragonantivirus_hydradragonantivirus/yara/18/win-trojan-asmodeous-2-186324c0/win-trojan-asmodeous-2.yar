rule Win_Trojan_Asmodeous_2
{
strings:
	$a0 = { f3f34b4b093af3c012dffe4a0ab3abab11494984a5252b6c6976cecf98131d5a5fd4c28b8e4362d6e8 }


condition:
	$a0
}