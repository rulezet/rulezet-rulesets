rule Win_Trojan_SillyOE_5
{
strings:
	$a0 = { cd217207e80500b44febf5c3c333c9e83500b002e82700b440b91501ba6400cd21b8015753 }


condition:
	$a0
}