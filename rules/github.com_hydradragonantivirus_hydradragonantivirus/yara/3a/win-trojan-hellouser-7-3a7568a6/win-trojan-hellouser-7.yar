rule Win_Trojan_HelloUser_7
{
strings:
	$a0 = { 021a20e8020087f75d87fe81ed080187f78db62c01e80200eb108b962e03b902028bfeac32c2aae2fac3 }


condition:
	$a0
}