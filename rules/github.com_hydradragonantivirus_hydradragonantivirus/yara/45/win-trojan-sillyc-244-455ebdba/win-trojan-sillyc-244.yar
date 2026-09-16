rule Win_Trojan_SillyC_244
{
strings:
	$a0 = { b44e29c9cd217207e80500b44febf5c3b8003de86400b43fb905008bd5cd21b43ecd21 }


condition:
	$a0
}