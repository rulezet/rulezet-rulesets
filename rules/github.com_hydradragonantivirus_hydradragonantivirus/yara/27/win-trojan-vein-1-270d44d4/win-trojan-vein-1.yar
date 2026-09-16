rule Win_Trojan_Vein_1
{
strings:
	$a0 = { 9e00cd2193b80057cd215251b440b9ed00ba0001cd21b80157595acd21b43ecd21b44febcbc345 }


condition:
	$a0
}