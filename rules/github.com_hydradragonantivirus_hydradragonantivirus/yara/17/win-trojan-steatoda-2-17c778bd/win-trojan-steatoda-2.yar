rule Win_Trojan_Steatoda_2
{
strings:
	$a0 = { 35cd2181fb999975068d9cfe00ffe38d9c0402432e80 }


condition:
	$a0
}