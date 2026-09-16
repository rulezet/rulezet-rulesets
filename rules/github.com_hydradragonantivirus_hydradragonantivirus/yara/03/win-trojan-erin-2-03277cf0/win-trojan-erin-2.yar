rule Win_Trojan_Erin_2
{
strings:
	$a0 = { ed0601b903008db6fc02bf000157f3a48d96ff02b41acd21b43b8d962903cd21e85f00b42acd2180fa1e754eb439 }


condition:
	$a0
}