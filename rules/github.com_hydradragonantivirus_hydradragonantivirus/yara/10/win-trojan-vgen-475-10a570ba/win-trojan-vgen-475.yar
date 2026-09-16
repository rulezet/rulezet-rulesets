rule Win_Trojan_VGEN_475
{
strings:
	$a0 = { 213d21337453b430cd213c07734bb82135cd21899ed3028c86d5028cd8488ec026a103002d }


condition:
	$a0
}