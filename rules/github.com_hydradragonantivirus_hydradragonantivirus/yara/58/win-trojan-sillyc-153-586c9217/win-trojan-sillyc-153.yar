rule Win_Trojan_SillyC_153
{
strings:
	$a0 = { 17013bc17508b43ecd21b44febcd2d03003e8986170233c0e82700b440b903008d961602cd21 }


condition:
	$a0
}