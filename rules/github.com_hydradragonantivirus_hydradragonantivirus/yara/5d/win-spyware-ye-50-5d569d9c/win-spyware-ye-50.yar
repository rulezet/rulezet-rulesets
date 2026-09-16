rule Win_Spyware_ye_50
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2ffd398e4a691c4e701d40aacaefa7 }


condition:
	$a0
}