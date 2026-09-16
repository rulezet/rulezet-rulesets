rule Win_Trojan_Cu_1
{
strings:
	$a0 = { e800005d81ed????b81818cd2181fb01c074558cd8488ed8 }


condition:
	$a0
}