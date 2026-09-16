rule Win_Trojan_XRes_5
{
strings:
	$a0 = { 5e83ee03061eb420cd210ac075638cd8488ed88b1e030083eb23b44acd21b448bb2200cd21488ec04026c706010008 }


condition:
	$a0
}