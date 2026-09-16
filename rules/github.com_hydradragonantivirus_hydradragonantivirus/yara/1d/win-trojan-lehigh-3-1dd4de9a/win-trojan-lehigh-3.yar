rule Win_Trojan_Lehigh_3
{
strings:
	$a0 = { cd21061f33d2b82125cd441f075bffb72102c3 }


condition:
	$a0
}