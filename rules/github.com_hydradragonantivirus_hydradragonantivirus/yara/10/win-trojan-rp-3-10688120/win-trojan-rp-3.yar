rule Win_Trojan_RP_3
{
strings:
	$a0 = { 044fff0d8b05b106d3e02dc0075050b801020e07bb007e8b0e257c8b16237ccd1358bb4c0087 }


condition:
	$a0
}