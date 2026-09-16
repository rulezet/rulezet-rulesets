rule Win_Trojan_SillyE_14
{
strings:
	$a0 = { 1f8c06af040e07bea104bfb104a5a5a5a533c0501fbe4800bfc104a5a5be8400bfc904a5a50e1fe805031ec516c904 }


condition:
	$a0
}