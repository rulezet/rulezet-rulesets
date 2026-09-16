rule Win_Trojan_Pakes_920
{
strings:
	$a0 = { 226d7f7c2a617578697f784c3d3e3a226f63612a[0-50]3d3a3f226f63612a }


condition:
	$a0
}