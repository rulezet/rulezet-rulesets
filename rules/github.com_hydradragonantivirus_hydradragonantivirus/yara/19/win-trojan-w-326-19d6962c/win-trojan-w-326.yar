rule Win_Trojan_W_326
{
strings:
	$a0 = { 81efa81f00002bfb893bcf58ababc747fa280000ee9683ee0ecd006850004100 }


condition:
	$a0
}