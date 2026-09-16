rule Win_Trojan_Mother_1
{
strings:
	$a0 = { 7d2c32ad0faa108cf640acab0aa05251ff32f00bf9caabdc7bfd90126a904650 }


condition:
	$a0
}