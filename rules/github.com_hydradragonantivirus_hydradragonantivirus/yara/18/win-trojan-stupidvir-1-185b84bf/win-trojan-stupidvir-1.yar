rule Win_Trojan_StupidVir_1
{
strings:
	$a0 = { 353428505e2937434329377d245f5f5f5f5f5f2d2d2d5468652d5374757069642d5669727573 }


condition:
	$a0
}