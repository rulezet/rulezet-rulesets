rule Win_Trojan_Mini_28
{
strings:
	$a0 = { 568bfdb9030083c70987f7f3a4be80008bd5b44efcb9ff0083c203cd2173039090c38bd683c21eb8014333c9 }


condition:
	$a0
}