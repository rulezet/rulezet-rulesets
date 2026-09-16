rule Win_Trojan_TinyDI_4
{
strings:
	$a0 = { 010e5650568cc880c4108ec08bfeb96c00f3a4bad400b41acd21ba6601b44ecd21baf200b8023dcd218bd8061f8bd749b43fcd21056c005033c9b8004299 }


condition:
	$a0
}