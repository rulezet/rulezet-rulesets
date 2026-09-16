rule Win_Trojan_Epsilon_1
{
strings:
	$a0 = { 2d028c1e2f028c1e3302ba5c00891631028c1e3702ba }


condition:
	$a0
}