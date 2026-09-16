rule Win_Trojan_Mandra_5
{
strings:
	$a0 = { cd213c887503e98400b800cabb4254cd2ffec074788ccb4b8edb8b1e0300b44a83eb2bcd21 }


condition:
	$a0
}