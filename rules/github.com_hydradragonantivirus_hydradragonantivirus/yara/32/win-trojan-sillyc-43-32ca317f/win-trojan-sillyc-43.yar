rule Win_Trojan_SillyC_43
{
strings:
	$a0 = { cd21723380bc8200e9742c33c9b8024299cd212d0300898486008bd6b98e0090b440cd2133 }


condition:
	$a0
}