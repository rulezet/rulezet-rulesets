rule Win_Trojan_Metsyn_1
{
strings:
	$a0 = { 1068215740008d45dcba04000000e817e0ffffc3e989daffffebeb5f5e5be8f3deffff000000ffffffff480000000d0a73796e2076312e36205b31342041 }


condition:
	$a0
}