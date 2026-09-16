rule Win_Trojan_GenVir_2
{
strings:
	$a0 = { 4041cd218bc3ebd62ea1220133f6508b5e10b8000233d2 }


condition:
	$a0
}