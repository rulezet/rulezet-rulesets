rule Win_Trojan_ScottsValley_1
{
strings:
	$a0 = { eb441e33c08ed88b368400a18600 }


condition:
	$a0
}