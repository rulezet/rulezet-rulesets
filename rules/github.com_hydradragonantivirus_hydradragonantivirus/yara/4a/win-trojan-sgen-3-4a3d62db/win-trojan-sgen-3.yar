rule Win_Trojan_SGEN_3
{
strings:
	$a0 = { 9003437bea7951bac0028bf28b16460f8a23fceb4590cd138a22b40081e1f0048a217510b85d10b99d01f2ae8a23 }


condition:
	$a0
}