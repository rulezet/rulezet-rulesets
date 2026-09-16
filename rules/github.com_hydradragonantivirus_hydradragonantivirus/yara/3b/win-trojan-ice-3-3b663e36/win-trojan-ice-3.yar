rule Win_Trojan_Ice_3
{
strings:
	$a0 = { 2acd215830f601d050e81200cd2558f716f0025872d7e80500cd2658ebcf89c2b419cd21b90100 }


condition:
	$a0
}