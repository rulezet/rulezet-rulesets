rule Win_Trojan_DelFiles_2
{
strings:
	$a0 = { 636f707920646f6e75742e626174203130342e424154 }

	$a1 = { 44454c20564d4d33322e4f3230 }


condition:
	$a0 and $a1
}