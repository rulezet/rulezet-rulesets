rule Win_Trojan_HelloUser_5
{
strings:
	$a0 = { e800005d81ed08018db62601e80200eb108b962703b90102 }


condition:
	$a0
}