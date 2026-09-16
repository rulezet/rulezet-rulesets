rule Win_Trojan_Vecna_7
{
strings:
	$a0 = { 33db8ed0bc007cfb8edbff0e1304cd12b106d3e08ec08bf4bf0000b90001f3a506686500cbfa }


condition:
	$a0
}