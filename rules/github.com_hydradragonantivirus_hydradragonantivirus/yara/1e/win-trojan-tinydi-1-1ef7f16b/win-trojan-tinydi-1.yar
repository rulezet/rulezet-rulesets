rule Win_Trojan_TinyDI_1
{
strings:
	$a0 = { 3dcd218bd8061f8bd749b43fcd210565005033c9b800 }


condition:
	$a0
}