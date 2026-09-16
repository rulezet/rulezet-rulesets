rule Win_Trojan_ErasePT_1
{
strings:
	$a0 = { 215152b000e82c00b91800ba8702b440cd21e81d00250f00b900028bd01e8cd8488ed8b440cd21 }


condition:
	$a0
}