rule Win_Trojan_757_1
{
strings:
	$a0 = { 0700fcf3a4585b9db800015350cb9c3d00c774db3d01c7 }


condition:
	$a0
}