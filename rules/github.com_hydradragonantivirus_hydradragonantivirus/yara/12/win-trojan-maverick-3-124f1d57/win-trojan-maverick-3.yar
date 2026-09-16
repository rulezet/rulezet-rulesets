rule Win_Trojan_Maverick_3
{
strings:
	$a0 = { 9733a2d464e014089cd45ee013305bd2a702d81b86127048f3d09113780db53380e6c4164bdfa199 }


condition:
	$a0
}