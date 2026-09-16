rule Win_Trojan_Trivial_431
{
strings:
	$a0 = { cd2189deb8014333c98d541ecd21b8023dcd2189db93b440b9ce00ba0001cd21b801578b4c16 }


condition:
	$a0
}