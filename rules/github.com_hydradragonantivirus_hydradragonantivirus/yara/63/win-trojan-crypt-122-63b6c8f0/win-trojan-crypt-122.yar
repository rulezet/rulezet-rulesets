rule Win_Trojan_Crypt_122
{
strings:
	$a0 = { 9c60e8000000005db8070000002be88db504fdffff8a063c0074128bf58db52cfdffff8a063c010f84 }


condition:
	$a0
}