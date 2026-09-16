rule Win_Trojan_AZ_1
{
strings:
	$a0 = { cd212e8b47fe2e3b0603017503eb2b90061eb462cd212e891eae02b82135cd218c067502891e7302ba0501b821 }


condition:
	$a0
}