rule Win_Trojan_Russel_4
{
strings:
	$a0 = { f5f927bd467d3586f5f97ee7fdf973cde69bb8be4e87e1eddec07ef1f6b2e6ac7cf1332f75c7f5f9 }


condition:
	$a0
}