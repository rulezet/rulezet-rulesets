rule Win_Trojan_Delwin_42
{
strings:
	$a0 = { 72656e2077696e646f7773205f5f5f5f5f5f5f5f5f[0-219]5f5f5f5f20636c73 }


condition:
	$a0
}