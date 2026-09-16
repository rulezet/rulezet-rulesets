rule Win_Trojan_Favor_1
{
strings:
	$a0 = { 32f6b90100b801020e07bb000bcd13b80103cd135a595bc30e07b80242b9ffffbac4ffe84301 }


condition:
	$a0
}