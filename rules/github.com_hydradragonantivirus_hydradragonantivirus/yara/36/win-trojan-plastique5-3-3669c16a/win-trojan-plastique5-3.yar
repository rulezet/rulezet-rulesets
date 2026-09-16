rule Win_Trojan_Plastique5_3
{
strings:
	$a0 = { 4bfccd213d78567512b8414bbf00 }


condition:
	$a0
}