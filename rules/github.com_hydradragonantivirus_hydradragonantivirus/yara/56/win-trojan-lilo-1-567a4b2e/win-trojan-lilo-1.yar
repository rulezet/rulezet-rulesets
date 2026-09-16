rule Win_Trojan_Lilo_1
{
strings:
	$a0 = { 6100fc51acb104d2c0aa59e2f6595f07c333dbb803 }


condition:
	$a0
}