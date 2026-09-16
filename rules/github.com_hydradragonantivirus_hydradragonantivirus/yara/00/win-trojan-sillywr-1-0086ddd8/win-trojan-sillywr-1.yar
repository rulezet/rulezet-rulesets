rule Win_Trojan_SillyWR_1
{
strings:
	$a0 = { 81efa71f00002bfb893bcf58ababc747fa280000ee9683ee0ecd006850004100 }


condition:
	$a0
}