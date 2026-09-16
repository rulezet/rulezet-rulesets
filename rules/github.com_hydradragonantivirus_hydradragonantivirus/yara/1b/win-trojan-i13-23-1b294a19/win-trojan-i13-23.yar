rule Win_Trojan_I13_23
{
strings:
	$a0 = { 1939291c0bf725ff0b7fd84c08b63b3dc5d53b26bcb4c5d57bf7e13a0a1cecf6bcb4b215194d06f4 }


condition:
	$a0
}