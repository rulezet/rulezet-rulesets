rule Win_Adware_Surfside_7
{
strings:
	$a0 = { 50e8affcffff84c05959741768003040006a0a8d85f0fcffff506a006a00e852ffffff }


condition:
	$a0
}