rule Win_Trojan_Popwin_31
{
strings:
	$a0 = { 907b6c62ca4539ca99627ae831ad7348e48f405fd0cc2a7dafeea2ba2de1fb08e32cacd9fc384681734f53d475ee363a6fd9cd617b5d44b0e369e4c734dbfd7dd38f7c25d7fda3f3272163dc101a8606 }


condition:
	$a0
}