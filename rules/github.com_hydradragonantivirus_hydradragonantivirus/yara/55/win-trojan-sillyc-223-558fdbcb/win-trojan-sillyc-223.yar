rule Win_Trojan_SillyC_223
{
strings:
	$a0 = { cd212e8b1e4301b43ecd210e1fb44fba5202cd217202eba9ba8000b41acd2132c0e670e671fe }


condition:
	$a0
}