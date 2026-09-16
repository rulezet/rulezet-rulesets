rule Win_Trojan_Star_3
{
strings:
	$a0 = { 8b1e6c04891ea90307b41abaab03cd21c70658032a00c7 }


condition:
	$a0
}