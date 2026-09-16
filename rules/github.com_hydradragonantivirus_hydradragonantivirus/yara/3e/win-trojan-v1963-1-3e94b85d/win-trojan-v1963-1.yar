rule Win_Trojan_V1963_1
{
strings:
	$a0 = { 0e07bb04098bfbabb080ab8cc8abb85c00ab8cc8abb86c00ab8cc8 }


condition:
	$a0
}