rule Win_Trojan_Delf_473
{
strings:
	$a0 = { ba04524000e85dfaffff84c0743f8d459050b902000000bad45140008b45fce87ffbffff8b4590e8e7f9ffff506a006a01e8f9eeffffa39c7940006a00a19c79400050e807efffff }


condition:
	$a0
}