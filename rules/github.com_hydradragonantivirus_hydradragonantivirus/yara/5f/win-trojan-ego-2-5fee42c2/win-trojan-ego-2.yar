rule Win_Trojan_Ego_2
{
strings:
	$a0 = { 378ab2ad33e86221d2d9e83a1bfcb0052a2d4f072090ff7ad9a091852a6dbd4be2903eb6908f83c207b225e5f0a6f39674ed085ccdf9e99a1d2e1bf06e16b8d2 }


condition:
	$a0
}