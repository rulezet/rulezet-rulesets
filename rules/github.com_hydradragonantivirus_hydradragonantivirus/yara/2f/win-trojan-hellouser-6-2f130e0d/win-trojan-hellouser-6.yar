rule Win_Trojan_HelloUser_6
{
strings:
	$a0 = { 87f75d87fe81ed080187f78db62c01e80200eb108b962a03b9fe018bfeac32c2aae2fac3 }


condition:
	$a0
}