rule Win_Trojan_TinyDI_2
{
strings:
	$a0 = { 010e56568cc880c4108ec08bfeb96500f3a4bad400b41acd21ba5f01b44ecd217230baf200b8023dcd218bd8061f8bd749b43fcd210565005033c9b80042 }


condition:
	$a0
}