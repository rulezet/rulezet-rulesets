rule Win_Trojan_SillyC_97
{
strings:
	$a0 = { e800005d83ed0487f78bf581c6ca00a5a5b41a8bd581c2ce00cd21b44e8bd581c2c400b9fe00cd217202eb0ab41aba }


condition:
	$a0
}