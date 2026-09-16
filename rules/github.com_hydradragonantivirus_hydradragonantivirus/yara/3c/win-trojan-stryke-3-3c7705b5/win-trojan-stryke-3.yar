rule Win_Trojan_Stryke_3
{
strings:
	$a0 = { fd00cd2172af58fec4c1e804a3f000b440ba0000b9fd00cd21729a32c0e80e007293b440ba }


condition:
	$a0
}