rule Win_Trojan_Wit_11
{
strings:
	$a0 = { eda11a04a31c04a11e04a34104a04f04a25004c6064f0400be5104bf5f04b90d00f3a4a12c00a3 }


condition:
	$a0
}