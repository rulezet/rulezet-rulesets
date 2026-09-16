rule Win_Trojan_DanishTiny_2
{
strings:
	$a0 = { 7407b44febdbeb5690b80057cd2152518b55018994 }


condition:
	$a0
}