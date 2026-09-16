rule Win_Trojan_Stoned_28
{
strings:
	$a0 = { ba1212b99419cd1aa113044848a31304b106d3e08ec0a3217cb90002be007c33fffcf3a42eff }


condition:
	$a0
}