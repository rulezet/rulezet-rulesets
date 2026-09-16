rule Win_Trojan_B_105
{
strings:
	$a0 = { c08ed8be4c00bf037ca5a51e07a113044848a31304b106d3e08ec0c7064c00 }


condition:
	$a0
}