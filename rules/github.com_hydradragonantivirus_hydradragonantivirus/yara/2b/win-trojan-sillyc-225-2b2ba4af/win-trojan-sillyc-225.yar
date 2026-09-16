rule Win_Trojan_SillyC_225
{
strings:
	$a0 = { cd212e8b36fcff8bde83c64281c39300b903008a0488074346e2f82e8b36fcff83c6408b1cb4 }


condition:
	$a0
}