rule Win_Trojan_SillyC_130
{
strings:
	$a0 = { f0008d54fd90cd215a5980c91fb80157cd21e80900 }


condition:
	$a0
}