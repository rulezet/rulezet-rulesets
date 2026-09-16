rule Win_Trojan_Wildy_2
{
strings:
	$a0 = { 06d3e08ec0eb06905b4d61785d2d40008ec0bf00018bf790b96201f3a48cc11e33c08ed850be8400bf5a01a5a5 }


condition:
	$a0
}